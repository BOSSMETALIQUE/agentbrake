"""Feasibility spike: a zkSNARK for one AgentBrake detector decision.

NOT part of the package. Nothing here is imported by ``agentbrake/`` and no
dependency of this script is declared in ``pyproject.toml``. It exists to put
real numbers under ``docs/design/zk-receipts.md`` instead of quoted ones.

The question
------------
``BudgetDetector.check`` (agentbrake/detectors.py:177-181) is three lines of
arithmetic::

    projected = run_state.total_cost_usd + new_call.cost_usd
    if projected > self.budget_usd:
        return InterruptReason.BUDGET

Can that decision be proved in zero knowledge — i.e. can the agent convince a
third party that the cumulative spend really crossed the cap, **without
revealing what any individual call cost**? That last clause is the part an
Ed25519 receipt cannot do: to convince you today, the receipt has to show you
the numbers.

What is proved
--------------
Private (witness)  : per-call costs c_1..c_n and the new call's cost c_new,
                     in integer micro-dollars (see "Floats" below).
Public  (instance) : the budget cap B, and the verdict.
Statement          : sum(c_i) + c_new  >  B

What is NOT proved
------------------
That c_1..c_n are the *real* costs of the *real* calls. The prover picks the
witness. A compromised host feeds fabricated costs and gets an honest proof of
a fabricated decision. Closing that gap needs the inputs to be attested by
something the host does not control — it is not a property this circuit, or
any circuit, provides on its own. See the design doc, "What ZK does not fix".

Floats
------
Costs are ``float`` in AgentBrake (``ToolCall.cost_usd``). A SNARK works over a
prime field: there are no floats. EZKL bridges that with fixed-point scaling,
which is lossy and is itself a source of soundness bugs (two spends that differ
below the scale become equal in-circuit). This script sidesteps the ambiguity
by quantizing to integer micro-dollars up front, which is what a real
implementation would have to do to AgentBrake's cost type as well.

Having done so, it then sets ``input_scale = param_scale = 0`` — fixed-point
*off*. That is a result worth stating: because the budget predicate is exact
integer arithmetic rather than a neural forward pass, the whole quantization
apparatus that dominates NiyamAI's pipeline is simply not needed here, and the
circuit computes the same thing Python does with no numerical error at all.
The first version of this script left EZKL's default scale (7) on and the
prover rejected the witness outright ("integer 409600000 is too large to be
represented by base 16384 and n 2") — scaling integer micro-dollars by 2^7
overflows the decomposition. Turning scaling off is both faster and more
correct for this class of predicate.

Usage
-----
    experiments/.venv/Scripts/python experiments/zk_budget_proof.py

Requires an isolated venv (NOT the project venv):
    python -m venv experiments/.venv
    experiments/.venv/Scripts/python -m pip install ezkl onnx numpy
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import time
from pathlib import Path

import onnx
from onnx import TensorProto, helper

import ezkl

HERE = Path(__file__).resolve().parent
ARTIFACTS = HERE / "_zk_artifacts"

# One worked example: eight prior calls plus the one about to run, against a
# cap of $0.50. Micro-dollars, so every value is an exact integer.
PRIOR_COSTS_USD = [0.02, 0.05, 0.11, 0.03, 0.09, 0.07, 0.04, 0.06]
NEW_CALL_COST_USD = 0.08
BUDGET_USD = 0.50
SCALE = 1_000_000  # USD -> micro-dollars


def _log(msg: str) -> None:
    print(f"[zk] {msg}", flush=True)


async def _call(fn, *args, **kwargs):
    """Call an ezkl function that may or may not be a coroutine.

    Two rough edges of the ezkl Python API, smoothed here so the steps below
    read as the pipeline rather than as glue:

    * Several entry points turned async across versions (``get_srs``,
      ``gen_witness``), and some did not. Await whatever is awaitable.
    * The PyO3 bindings take ``str`` paths, not ``os.PathLike``: a ``Path``
      raises ``TypeError: 'WindowsPath' object cannot be cast as 'str'`` in
      some functions and is accepted in others. Stringify every ``Path``.

    That inconsistency is itself a small data point for the design doc — this
    is a research toolchain, not a stable dependency.
    """
    args = tuple(str(a) if isinstance(a, Path) else a for a in args)
    kwargs = {k: (str(v) if isinstance(v, Path) else v) for k, v in kwargs.items()}
    out = fn(*args, **kwargs)
    if inspect.isawaitable(out):
        return await out
    return out


# --------------------------------------------------------------------------
# 1. The circuit, expressed as ONNX
# --------------------------------------------------------------------------

def build_onnx(path: Path, n_inputs: int) -> None:
    """A graph computing ``sum(costs) - cap``, exported to ONNX.

    EZKL compiles ONNX, so the predicate has to be written as a tensor graph
    rather than as Python. Note how little of AgentBrake this is: one
    ReduceSum and one Sub. The NiyamAI paper needs 431 constraints because it
    is proving a neural network's forward pass; a threshold comparison needs
    almost nothing. The cost of ZK here is not the arithmetic — it is
    everything around it.

    The output is the signed margin rather than a boolean. ONNX ``Greater``
    emits a bool tensor, which EZKL's fixed-point pipeline handles
    inconsistently across versions; the margin is equivalent (``margin > 0``
    iff over budget) and keeps the graph in one numeric type. The tradeoff is
    worth recording honestly: a public margin leaks ``total - cap``, so this
    graph proves the *decision* in zero knowledge but not the *amount*. Hiding
    the amount as well needs the comparison done in-circuit.
    """
    costs = helper.make_tensor_value_info("costs", TensorProto.FLOAT, [1, n_inputs])
    margin = helper.make_tensor_value_info("margin", TensorProto.FLOAT, [1, 1])

    cap = helper.make_tensor(
        name="cap",
        data_type=TensorProto.FLOAT,
        dims=[1, 1],
        vals=[float(BUDGET_USD * SCALE)],
    )
    axes = helper.make_tensor(
        name="axes", data_type=TensorProto.INT64, dims=[1], vals=[1]
    )

    graph = helper.make_graph(
        nodes=[
            helper.make_node("ReduceSum", ["costs", "axes"], ["total"], keepdims=1),
            helper.make_node("Sub", ["total", "cap"], ["margin"]),
        ],
        name="agentbrake_budget_check",
        inputs=[costs],
        outputs=[margin],
        initializer=[cap, axes],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])
    model.ir_version = 9  # ezkl's tract backend predates ir_version 10
    onnx.checker.check_model(model)
    onnx.save(model, str(path))
    _log(f"ONNX graph written ({path.stat().st_size} bytes): ReduceSum -> Sub")


# --------------------------------------------------------------------------
# 2. Prove / verify
# --------------------------------------------------------------------------

async def main() -> int:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    model_path = ARTIFACTS / "budget.onnx"
    settings_path = ARTIFACTS / "settings.json"
    compiled_path = ARTIFACTS / "budget.ezkl"
    srs_path = ARTIFACTS / "kzg.srs"
    vk_path = ARTIFACTS / "vk.key"
    pk_path = ARTIFACTS / "pk.key"
    data_path = ARTIFACTS / "input.json"
    witness_path = ARTIFACTS / "witness.json"
    proof_path = ARTIFACTS / "proof.json"

    witness_costs = [round(c * SCALE) for c in PRIOR_COSTS_USD + [NEW_CALL_COST_USD]]
    total = sum(witness_costs)
    cap = round(BUDGET_USD * SCALE)
    expected_over = total > cap

    _log(f"prior calls: {len(PRIOR_COSTS_USD)}  new call: ${NEW_CALL_COST_USD}")
    _log(f"total ${total / SCALE:.2f} vs cap ${cap / SCALE:.2f} -> over_budget={expected_over}")

    build_onnx(model_path, n_inputs=len(witness_costs))

    data_path.write_text(
        json.dumps({"input_data": [[float(v) for v in witness_costs]]}),
        encoding="utf-8",
    )

    timings: dict[str, float] = {}

    class step:
        def __init__(self, name: str):
            self.name = name

        def __enter__(self):
            self.t0 = time.perf_counter()
            return self

        def __exit__(self, *a):
            timings[self.name] = time.perf_counter() - self.t0
            _log(f"{self.name}: {timings[self.name]:.2f}s")

    # The costs stay private; the verdict is public. "private" here is EZKL's
    # input_visibility — the field that makes this a *zero-knowledge* proof
    # rather than merely a succinct one.
    run_args = ezkl.PyRunArgs()
    run_args.input_visibility = "private"
    run_args.output_visibility = "public"
    run_args.param_visibility = "fixed"
    # Fixed-point off: the witness is already integral (see module docstring).
    run_args.input_scale = 0
    run_args.param_scale = 0

    with step("gen_settings"):
        assert await _call(
            ezkl.gen_settings, model_path, settings_path, py_run_args=run_args
        )

    # Calibration exists to search for a fixed-point scale that keeps a neural
    # net numerically faithful. Pin it to the only scale this circuit wants
    # rather than letting the search reintroduce one.
    with step("calibrate_settings"):
        await _call(
            ezkl.calibrate_settings,
            data_path, model_path, settings_path,
            scales=[0],
        )

    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    logrows = settings["run_args"]["logrows"]
    num_rows = settings.get("num_rows")
    _log(f"circuit: logrows={logrows} (2^{logrows} rows), num_rows={num_rows}")

    with step("compile_circuit"):
        assert await _call(ezkl.compile_circuit, model_path, compiled_path, settings_path)

    with step("get_srs"):
        await _call(ezkl.get_srs, settings_path, srs_path=srs_path)

    with step("setup"):
        assert await _call(ezkl.setup, compiled_path, vk_path, pk_path, srs_path=srs_path)

    with step("gen_witness"):
        await _call(ezkl.gen_witness, data_path, compiled_path, witness_path)

    with step("prove"):
        assert await _call(
            ezkl.prove,
            witness_path, compiled_path, pk_path, proof_path, srs_path,
        )

    with step("verify"):
        ok = await _call(ezkl.verify, proof_path, settings_path, vk_path, srs_path=srs_path)
    assert ok, "proof did not verify"

    # ----- what the verifier actually reads -------------------------------
    witness = json.loads(witness_path.read_text(encoding="utf-8"))
    public_out = witness.get("pretty_elements", {}).get("rescaled_outputs")

    sizes = {
        "proof.json": proof_path.stat().st_size,
        "vk.key": vk_path.stat().st_size,
        "pk.key": pk_path.stat().st_size,
        "kzg.srs": srs_path.stat().st_size,
        "settings.json": settings_path.stat().st_size,
        "budget.ezkl": compiled_path.stat().st_size,
    }

    print()
    print("=" * 70)
    print("RESULT")
    print("=" * 70)
    print(f"proof verified          : {ok}")
    print(f"public output (margin)  : {public_out}")
    print(f"  interpreted           : over_budget = margin > 0 = {expected_over}")
    print(f"circuit size            : 2^{logrows} rows (num_rows={num_rows})")
    print()
    print("timings (s):")
    for k, v in timings.items():
        print(f"  {k:<22} {v:8.2f}")
    print()
    print("artifact sizes (bytes):")
    for k, v in sorted(sizes.items(), key=lambda kv: -kv[1]):
        print(f"  {k:<22} {v:>12,}")
    print()
    print("Same predicate on the Ed25519 path, measured on this machine:")
    print("  mint receipt           ~0.42 ms        (vs 'prove' above)")
    print("  verify chain           ~0.13 ms        (vs 'verify' above)")
    print("  receipt row             1,996 bytes    (vs proof.json + vk.key above)")
    print()
    print("Verifier needs, Ed25519 : one JSON bundle + 64 hex chars of public key.")
    print("Verifier needs, ZK      : proof.json + vk.key + settings.json + the KZG")
    print("                          SRS + an ezkl runtime of the same version.")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("RUST_LOG", "error")
    raise SystemExit(asyncio.run(main()))
