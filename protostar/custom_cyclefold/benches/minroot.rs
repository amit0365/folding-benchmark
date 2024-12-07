use std::fs::File;
use std::io::Write;
use std::time::Instant;
use std::time::Duration;
use criterion::black_box;
use criterion::BenchmarkId;
use std::collections::HashMap;
use plonkish_backend::util::test::seeded_std_rng;
use halo2_proofs::halo2curves::{bn256::{self, Bn256}, grumpkin};
use plonkish_backend::accumulation::protostar::ivc::halo2::test::{run_protostar_hyperplonk_ivc_minroot_preprocess, run_protostar_hyperplonk_ivc_prove};
use criterion::{criterion_group, criterion_main, Criterion};
use plonkish_backend::pcs::multilinear::{Gemini, MultilinearIpa};
use plonkish_backend::pcs::univariate::UnivariateKzg;
use plonkish_backend::pcs::PolynomialCommitmentScheme;

fn bench_gemini_kzg_ipa_protostar_hyperplonk_ivc(c: &mut Criterion) {
    let num_steps = 10;
    let num_iters_steps = vec![1024, 2048, 4096, 8192, 16384];
    let (mut primary_circuits, mut secondary_circuits, mut pp_vec, mut vp_vec) 
        = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    
    for (i, &num_iters) in num_iters_steps.iter().enumerate() {
        let primary_num_vars = 14 + i;
        let cyclefold_num_vars = 10;
        let primary_params = UnivariateKzg::setup(1 << (primary_num_vars + 4), 0, &mut seeded_std_rng()).unwrap();
        let cyclefold_params = MultilinearIpa::setup(1 << (cyclefold_num_vars + 4), 0, &mut seeded_std_rng()).unwrap();

        let (primary_circuit, secondary_circuit, ivc_pp, ivc_vp)
            = run_protostar_hyperplonk_ivc_minroot_preprocess::<
                bn256::G1Affine,
                Gemini<UnivariateKzg<Bn256>>,
                MultilinearIpa<grumpkin::G1Affine>,
            >(num_iters,primary_num_vars, primary_params, cyclefold_num_vars, cyclefold_params);
        
        primary_circuits.push(primary_circuit);
        secondary_circuits.push(secondary_circuit);
        pp_vec.push(ivc_pp);
        vp_vec.push(ivc_vp);
    }

    let mut group = c.benchmark_group("Halo2lib Protostar Cyclefold IVC");
    group.sample_size(10);

    let mut results = Vec::new();
    for (i, num_iters) in num_iters_steps.iter().enumerate() {
      let mut time = HashMap::new();
        let test_name = format!("entire_process_{}", num_iters);
        let benchmark_id = BenchmarkId::new(test_name, num_iters);
        group.bench_function(benchmark_id, |b| {
          b.iter_custom(|iters| {
              let start = Instant::now();
              for _ in 0..iters {
                  black_box(run_protostar_hyperplonk_ivc_prove(&mut primary_circuits[i], &mut secondary_circuits[i], &pp_vec[i], &vp_vec[i], *num_iters, num_steps));
              }
              let elapsed = start.elapsed();
              let _ = *time.entry(num_iters)
                  .and_modify(|e| *e += elapsed)
                  .or_insert(elapsed);
              elapsed
          })
      });

      let iterations = 10; // Replace this with the actual iteration count used in iter_custom.
      let total_duration = time.entry(num_iters).or_insert(Duration::ZERO).as_millis();
      let average_execution_time = total_duration / iterations;
      results.push((num_iters, average_execution_time));
    }

    group.finish();

    let mut file = File::create("../../benchmark_results/halo2_minroot_custom_cyclefold.md").expect("Failed to create file");
    writeln!(file, "| Num Steps  | Num Iters per step | Execution Time (ms) | Primary_circuit_size | Secondary_circuit_size |").expect("Failed to write to file");
    writeln!(file, "|------------|--------------------|---------------------|----------------------|------------------------|").expect("Failed to write to file");
    for (i, (num_iters, duration)) in results.iter().enumerate() {
        writeln!(
            file,
            "| {}         | {}               | {:?} ms             | {:?}                | {:?}                  |",
            num_steps, num_iters, duration, (pp_vec[i].primary_pp.witness_count - pp_vec[i].primary_pp.copy_count), (pp_vec[i].cyclefold_pp.witness_count - pp_vec[i].cyclefold_pp.copy_count)
        ).expect("Failed to write to file");
    }
}

fn minroot_protostar_cyclefold(c: &mut Criterion) {
    bench_gemini_kzg_ipa_protostar_hyperplonk_ivc(c);
}

criterion_group!(benches, minroot_protostar_cyclefold);
criterion_main!(benches);
