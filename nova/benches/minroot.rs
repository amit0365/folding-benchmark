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
  use std::fs::File;
  use std::io::Write;

  type E1 = Bn256EngineKZG;
  type E2 = GrumpkinEngine;
  type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
  type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
  type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
  type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK
  
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
fn bench_nova_ivc(c: &mut Criterion) {

    let num_iters_per_step = 1024;
    let circuit_primary = MinRootCircuit {
      seq: vec![
        MinRootIteration {
          x_i: <E1 as Engine>::Scalar::zero(),
          y_i: <E1 as Engine>::Scalar::zero(),
          x_i_plus_1: <E1 as Engine>::Scalar::zero(),
          y_i_plus_1: <E1 as Engine>::Scalar::zero(),
        };
        num_iters_per_step
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

    let num_steps_values = vec![10, 20];
    let mut group = c.benchmark_group("NOVA IVC");

    group.sample_size(10);

    let mut results = Vec::new();
    for &num_steps in &num_steps_values {
        let test_name = format!("entire_process_{}", num_steps);
        group.bench_function(&test_name, |b| {
            b.iter_custom(|_iters| nova_ivc(num_steps, num_iters_per_step, pp.clone(), circuit_secondary.clone()))
        });

        let exec_time = nova_ivc(num_steps, num_iters_per_step, pp.clone(), circuit_secondary.clone());
        results.push((num_steps, exec_time));
    }

    group.finish();

    let mut file = File::create("../benchmark_results/nova_minroot.md").expect("Failed to create file");
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