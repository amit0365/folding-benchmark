use nova::minroot::{nova_ivc, MinRootCircuit, MinRootIteration};
use nova_snark::{
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{
      circuit::TrivialCircuit,
      snark::RelaxedR1CSSNARKTrait,
      Engine, 
    },
    PublicParams,
  };
  use std::{collections::HashMap, fs::File, time::{Duration, Instant}};
  use std::io::Write;

  type E1 = Bn256EngineKZG;
  type E2 = GrumpkinEngine;
  type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
  type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
  type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
  type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK
  
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
fn bench_nova_ivc(c: &mut Criterion) {
    let mut primary_circuits = Vec::new();
    let mut secondary_circuits = Vec::new();
    let mut pp_vec = Vec::new();
    let num_iters_per_step = vec![1000, 9000, 25000, 58000, 100000];
    for num_iters in &num_iters_per_step {
      let circuit_primary = MinRootCircuit {
          seq: vec![
        MinRootIteration {
          i: <E1 as Engine>::Scalar::zero(),
          x_i: <E1 as Engine>::Scalar::zero(),
          y_i: <E1 as Engine>::Scalar::zero(),
          i_plus_1: <E1 as Engine>::Scalar::zero(),
          x_i_plus_1: <E1 as Engine>::Scalar::zero(),
          y_i_plus_1: <E1 as Engine>::Scalar::zero(),
            };
            *num_iters
          ],
        };

      let circuit_secondary = TrivialCircuit::default();
      let pp = PublicParams::<
        E1,
        E2,
        MinRootCircuit<<E1 as Engine>::GE>,
        TrivialCircuit<<E2 as Engine>::Scalar>,
      >::setup(
      &circuit_primary,
      &circuit_secondary,
      &*S1::ck_floor(),
      &*S2::ck_floor(),
      )
      .unwrap();

      pp_vec.push(pp);
      primary_circuits.push(circuit_primary);
      secondary_circuits.push(circuit_secondary);
    }

    let num_steps = 10;
    let mut group = c.benchmark_group("NOVA IVC");

    group.sample_size(10);

    let mut results = Vec::new();
    for (i, num_iters) in num_iters_per_step.iter().enumerate() {
      let mut time = HashMap::new();
        let test_name = format!("entire_process_{}", num_iters);
        let benchmark_id = BenchmarkId::new(test_name, num_iters);
        group.bench_function(benchmark_id, |b| {
          b.iter_custom(|iters| {
              let start = Instant::now();
              for _ in 0..iters {
                  black_box(nova_ivc(num_steps, *num_iters, pp_vec[i].clone(), secondary_circuits[i].clone()));
              }
              let elapsed = start.elapsed();
              let _ = *time.entry(*num_iters)
                  .and_modify(|e| *e += elapsed)
                  .or_insert(elapsed);
              elapsed
          })
      });

      let iterations = 10; // Replace this with the actual iteration count used in iter_custom.
      let total_duration = time.entry(*num_iters).or_insert(Duration::ZERO).as_millis();
      let average_execution_time = total_duration / iterations;
      results.push((*num_iters, average_execution_time));
    }

    group.finish();

    let mut file = File::create("../benchmark_results/nova_minroot_same2.md").expect("Failed to create file");
    writeln!(file, "| Num Steps  |     K      | Num Iters per step | Execution Time (ms) | Primary_circuit_size | Secondary_circuit_size |").expect("Failed to write to file");
    writeln!(file, "|------------|------------|--------------------|---------------------|----------------------|------------------------|").expect("Failed to write to file");
    for (i, (num_iters, duration)) in results.iter().enumerate() {
        writeln!(
            file,
            "| {}         | {}         | {}               | {:?} ms             | {:?}                | {:?}                  |",
            num_steps, pp_vec[i].ck_log2_len().0, num_iters, duration, pp_vec[i].num_constraints().0, pp_vec[i].num_constraints().1
        ).expect("Failed to write to file");
    }
}

fn minroot_nova(c: &mut Criterion) {
    bench_nova_ivc(c);
}

criterion_group!(benches, minroot_nova);
criterion_main!(benches);