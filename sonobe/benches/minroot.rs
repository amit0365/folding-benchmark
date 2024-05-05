use folding_schemes::folding::nova::Nova;
use sonobe::minroot::MinRootCircuit;
use std::{fs::File, time::Instant};
use std::io::Write;
use folding_schemes::commitment::pedersen::Pedersen;
use folding_schemes::FoldingScheme;
use sonobe::utils::test_nova_setup;

use ark_pallas::{constraints::GVar, Fr, Projective};
use ark_vesta::{constraints::GVar as GVar2, Projective as Projective2};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_nova_ivc(c: &mut Criterion) {
  let num_iters_per_step = 1024;
  let initial_state = vec![Fr::from(0_u32), Fr::from(1_u32)];

  let circuit_primary = MinRootCircuit::<Fr>::new(vec![Fr::from(0_u32), Fr::from(1_u32)], 1024);
    
    type NOVA = Nova<
      Projective,
      GVar,
      Projective2,
      GVar2,
      MinRootCircuit<Fr>,
      Pedersen<Projective>,
      Pedersen<Projective2>,
  >;

    let (prover_params, _verifier_params) =
     test_nova_setup::<MinRootCircuit<Fr>>(circuit_primary.clone());

    let mut folding_scheme = NOVA::init(&prover_params, circuit_primary, initial_state.clone()).unwrap();

    let num_steps_values = vec![10, 20];
    let mut group = c.benchmark_group("NOVA IVC");

    group.sample_size(10);

    let mut results = Vec::new();
    for &num_steps in &num_steps_values {
        let test_name = format!("entire_process_{}", num_steps);
        group.bench_function(&test_name, |b| {
            b.iter_custom(|_iters| {
              let start = Instant::now();
              for _i in 0..num_steps {
                folding_scheme.0.prove_step().unwrap();
            }
              start.elapsed()
            })
        });

        let exec_time = 
        {
            let start = Instant::now();
            for _i in 0..num_steps {
                folding_scheme.0.prove_step().unwrap();
            }
            start.elapsed()
        };
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
            num_steps, num_iters_per_step, duration.as_millis(), folding_scheme.1, folding_scheme.2 
        ).expect("Failed to write to file");
    }
}

fn minroot_nova(c: &mut Criterion) {
    bench_nova_ivc(c);
}

criterion_group!(benches, minroot_nova);
criterion_main!(benches);