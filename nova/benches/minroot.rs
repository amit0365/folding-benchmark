use nova::minroot::{nova_ivc, MinRootCircuit, MinRootIteration};
use nova_snark::{
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{
      circuit::{StepCircuit, TrivialCircuit},
      snark::RelaxedR1CSSNARKTrait,
      Engine, Group,
    },
    CompressedSNARK, PublicParams, RecursiveSNARK,
  };
  use num_bigint::BigUint;
  use std::time::Instant;
  
  type E1 = Bn256EngineKZG;
  type E2 = GrumpkinEngine;
  type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
  type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
  type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
  type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK
  
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_nova_ivc(c: &mut Criterion) {
    let num_steps_values = vec![5, 10, 20]; //, 100, 1000, 10000];
    let mut group = c.benchmark_group("NOVA IVC");

    group.sample_size(10);

    let num_iters_per_step = 1024;
    // number of iterations of MinRoot per Nova's recursive step
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

    for &num_steps in &num_steps_values {
        let test_name = BenchmarkId::new("entire_process", num_steps);
        
        group.bench_with_input(test_name, &num_steps, |b, &num_steps| {
            b.iter(|| {
                nova_ivc(num_steps, num_iters_per_step, pp.clone(), circuit_secondary.clone());
            });
        });
    }

    group.finish();
}

fn minroot_nova(c: &mut Criterion) {
    bench_nova_ivc(c);
}

criterion_group!(benches, minroot_nova);
criterion_main!(benches);