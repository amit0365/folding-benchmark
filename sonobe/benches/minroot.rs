use folding_schemes::folding::nova::Nova;
use sonobe::minroot::{nova_ivc, MinRootCircuit, MinRootIteration};
use num_bigint::BigUint;
use std::{fs::File, time::{Duration, Instant}};
use std::io::{Write, Result};
use folding_schemes::commitment::pedersen::Pedersen;
use folding_schemes::frontend::FCircuit;
use folding_schemes::FoldingScheme;
use sonobe::utils::test_nova_setup;

// use ark_bn254::{Fq, Fr, G1Projective as Projective};
use ark_pallas::{constraints::GVar, Fr, Projective};
use ark_vesta::{constraints::GVar as GVar2, Projective as Projective2};
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_nova_ivc(c: &mut Criterion) {
  let num_iters_per_step = 1024;
  let initial_state = vec![Fr::from(0_u32), Fr::from(0_u32)];

    let circuit_primary = MinRootCircuit {
      seq: vec![
        MinRootIteration {
          x_i: Fr::from(0_u32),
          y_i: Fr::from(0_u32),
          x_i_plus_1: Fr::from(0_u32),
          y_i_plus_1: Fr::from(0_u32),
        };
        num_iters_per_step
      ],
    };
    
    type NOVA = Nova<
      Projective,
      GVar,
      Projective2,
      GVar2,
      MinRootCircuit<Fr>,
      Pedersen<Projective>,
      Pedersen<Projective2>,
  >;

    let (prover_params, verifier_params) =
     test_nova_setup::<MinRootCircuit<Fr>>(circuit_primary.clone());

    let mut folding_scheme = NOVA::init(&prover_params, circuit_primary, initial_state.clone()).unwrap();


    let start = Instant::now();
    nova_ivc(*num_steps, num_iters_per_step, pp, circuit_secondary);
    start.elapsed()

    let num_steps_values = vec![10, 20];
    let mut group = c.benchmark_group("NOVA IVC");

    group.sample_size(10);

    let mut results = Vec::new();
    for &num_steps in &num_steps_values {
        let test_name = format!("entire_process_{}", num_steps);
        group.bench_function(&test_name, |b| {
            b.iter_custom(|_iters| run_benchmark(&num_steps))
        });

        let exec_time = run_benchmark(&num_steps);
        results.push((num_steps, exec_time));
    }

    group.finish();

    let mut file = File::create("../benchmark_results/sonobe_nova_minroot.md").expect("Failed to create file");
    writeln!(file, "| Num Steps  | Num Iters per step | Execution Time (ms) | Primary_circuit_size | Secondary_circuit_size |").expect("Failed to write to file");
    writeln!(file, "|------------|--------------------|---------------------|----------------------|------------------------|").expect("Failed to write to file");
    for (num_steps, duration) in results {
        writeln!(
            file,
            "| {}         | {}               | {:?} ms             | {:?}                | {:?}                  |",
            num_steps, num_iters_per_step, duration.as_millis(), pp.num_constraints().0, pp.num_constraints().1
        ).expect("Failed to write to file");
    }
}

fn minroot_nova(c: &mut Criterion) {
    bench_nova_ivc(c);
}

criterion_group!(benches, minroot_nova);
criterion_main!(benches);