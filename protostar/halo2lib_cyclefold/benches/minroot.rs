use std::fs::File;
use std::io::Write;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::halo2curves::{bn256::{self, Bn256}, grumpkin};
use plonkish_backend::accumulation::protostar::ivc::halo2::test::{run_protostar_hyperplonk_ivc_minroot_preprocess, run_protostar_hyperplonk_ivc_prove};
use criterion::{criterion_group, criterion_main, Criterion};
use plonkish_backend::pcs::multilinear::{Gemini, MultilinearIpa};
use plonkish_backend::pcs::univariate::UnivariateKzg;

fn bench_gemini_kzg_ipa_protostar_hyperplonk_ivc(c: &mut Criterion) {
    let primary_circuit_params = BaseCircuitParams {
        k: 19,
        num_advice_per_phase: vec![1],
        num_lookup_advice_per_phase: vec![1],
        num_fixed: 1,
        lookup_bits: Some(13),
        num_instance_columns: 1,
    };
    let cyclefold_circuit_params = BaseCircuitParams {
        k: 17,
        num_advice_per_phase: vec![1],
        num_lookup_advice_per_phase: vec![0],
        num_fixed: 1,
        lookup_bits: Some(1),
        num_instance_columns: 1,
    };
    let (primary_circuit, secondary_circuit, ivc_pp, ivc_vp, primary_size, secondary_size)
        = run_protostar_hyperplonk_ivc_minroot_preprocess::<
            bn256::G1Affine,
            Gemini<UnivariateKzg<Bn256>>,
            MultilinearIpa<grumpkin::G1Affine>,
        >(primary_circuit_params, cyclefold_circuit_params);

    let num_steps_values = vec![10, 20]; //, 100, 1000, 10000];
    let mut group = c.benchmark_group("Halo2lib Protostar Cyclefold IVC");

    group.sample_size(10);

    let mut results = Vec::new();
    for &num_steps in &num_steps_values {
        let test_name = format!("entire_process_{}", num_steps);
        group.bench_function(&test_name, |b| {
            b.iter_custom(|_iters| run_protostar_hyperplonk_ivc_prove(primary_circuit.clone(), secondary_circuit.clone(), ivc_pp.clone(), ivc_vp.clone(), num_steps))
        });

        let exec_time = run_protostar_hyperplonk_ivc_prove(primary_circuit.clone(), secondary_circuit.clone(), ivc_pp.clone(), ivc_vp.clone(), num_steps);
        results.push((num_steps, exec_time));
    }

    group.finish();
    let num_iters_per_step = primary_circuit.circuit().step_circuit.clone().into_inner().num_iters_per_step;
    let mut file = File::create("../../benchmark_results/halo2lib_minroot_protostar_cyclefold.md").expect("Failed to create file");
    writeln!(file, "| Num Steps  | Num Iters per step | Execution Time (ms) | Primary_circuit_size | Secondary_circuit_size |").expect("Failed to write to file");
    writeln!(file, "|------------|--------------------|---------------------|----------------------|------------------------|").expect("Failed to write to file");
    for (num_steps, duration) in results {
        writeln!(
            file,
            "| {}         | {}               | {:?} ms             | {:?}                | {:?}                  |",
            num_steps, num_iters_per_step, duration.as_millis(), primary_size, secondary_size
        ).expect("Failed to write to file");
    }
}

fn minroot_protostar_cyclefold(c: &mut Criterion) {
    bench_gemini_kzg_ipa_protostar_hyperplonk_ivc(c);
}

criterion_group!(benches, minroot_protostar_cyclefold);
criterion_main!(benches);
