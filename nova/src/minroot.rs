//! Demonstrates how to use Nova to produce a recursive proof of the correct execution of
//! iterations of the `MinRoot` function, thereby realizing a Nova-based verifiable delay function (VDF).
//! We execute a configurable number of iterations of the `MinRoot` function per step of Nova's recursion.
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::Field;
use nova_snark::{
  provider::{Bn256EngineKZG, GrumpkinEngine},
  traits::{
    circuit::{StepCircuit, TrivialCircuit},
    snark::RelaxedR1CSSNARKTrait,
    Engine, Group,
  },
  PublicParams, RecursiveSNARK,
};
use num_bigint::BigUint;
use std::time::{Duration, Instant};

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK

#[derive(Clone, Debug)]
pub struct MinRootIteration<G: Group> {
  pub i: G::Scalar,
  pub x_i: G::Scalar,
  pub y_i: G::Scalar,
  pub i_plus_1: G::Scalar,
  pub x_i_plus_1: G::Scalar,
  pub y_i_plus_1: G::Scalar,
}

impl<G: Group> MinRootIteration<G> {
  // produces a sample non-deterministic advice, executing one invocation of MinRoot per step
  fn new(num_iters: usize, i_0: &G::Scalar, x_0: &G::Scalar, y_0: &G::Scalar) -> (Vec<G::Scalar>, Vec<Self>) {
    // although this code is written generically, it is tailored to Pallas' scalar field
    // (p - 3 / 5)
    let exp = BigUint::parse_bytes(
      b"23158417847463239084714197001737581570690445185553317903743794198714690358477",
      10,
    )
    .unwrap();

    let mut res = Vec::new();
    let mut i = *i_0;
    let mut x_i = *x_0;
    let mut y_i = *y_0;
    for _ii in 0..num_iters {
      let x_i_plus_1 = (x_i + y_i).pow_vartime(exp.to_u64_digits()); // computes the fifth root of x_i + y_i

      // sanity check
      let sq = x_i_plus_1 * x_i_plus_1;
      let quad = sq * sq;
      let fifth = quad * x_i_plus_1;
      debug_assert_eq!(fifth, x_i + y_i);   

      let y_i_plus_1 = x_i + i;
      let i_plus_1 = i + G::Scalar::ONE;

      res.push(Self {
        i,
        x_i,
        y_i,
        i_plus_1,
        x_i_plus_1,
        y_i_plus_1,
      });

      i = i_plus_1;
      x_i = x_i_plus_1;
      y_i = y_i_plus_1;
    }

    let z0 = vec![*i_0, *x_0, *y_0];

    (z0, res)
  }
}

#[derive(Clone, Debug)]
pub struct MinRootCircuit<G: Group> {
  pub seq: Vec<MinRootIteration<G>>,
}

impl<G: Group> StepCircuit<G::Scalar> for MinRootCircuit<G> {
  fn arity(&self) -> usize {
    3
  }

  fn synthesize<CS: ConstraintSystem<G::Scalar>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<G::Scalar>],
  ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
    let mut z_out: Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> =
      Err(SynthesisError::AssignmentMissing);

    // variables to hold running x_i and y_i
    let mut i = z[0].clone();
    let mut x_i = z[1].clone();
    let mut y_i = z[2].clone();
    for ii in 0..self.seq.len() {
      // non deterministic advice
      let i_plus_1 = AllocatedNum::alloc(cs.namespace(|| format!("i_plus_1_iter_{}", ii)), || {
        Ok(self.seq[ii].i_plus_1)
      })?;
      let x_i_plus_1 =
        AllocatedNum::alloc(cs.namespace(|| format!("x_i_plus_1_iter_{}", ii)), || {
          Ok(self.seq[ii].x_i_plus_1)
        })?;
      let y_i_plus_1 =
        AllocatedNum::alloc(cs.namespace(|| format!("y_i_plus_1_iter_{}", ii)), || {
          Ok(self.seq[ii].y_i_plus_1)
        })?;

      // check the following conditions hold:
      // (i) x_i_plus_1 = (x_i + y_i)^{1/5}, which can be more easily checked with x_i_plus_1^5 = x_i + y_i

      let x_i_plus_1_sq =
        x_i_plus_1.square(cs.namespace(|| format!("x_i_plus_1_sq_iter_{}", ii)))?;
      let x_i_plus_1_quad =
        x_i_plus_1_sq.square(cs.namespace(|| format!("x_i_plus_1_quad_{}", ii)))?;
      cs.enforce(
        || format!("x_i_plus_1_quad * x_i_plus_1 = x_i + y_i iter_{}", ii),
        |lc| lc + x_i_plus_1_quad.get_variable(),
        |lc| lc + x_i_plus_1.get_variable(),
        |lc| lc + x_i.get_variable() + y_i.get_variable(),
      );

      // (ii) y_i_plus_1 = x_i + i
      cs.enforce(
        || format!("y_i_plus_1 = x_i + i  iter_{}", ii),
        |lc| lc + y_i_plus_1.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + x_i.get_variable() + i.get_variable(),
      );

      // (ii) i_plus_1 = i + i
      cs.enforce(
        || format!("i_plus_1 = i + i  iter_{}", ii),
        |lc| lc + i_plus_1.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + i.get_variable() + CS::one(),
      );

      // return (i_plus_1, x_i_plus_1, y_i_plus_1)
      if ii == self.seq.len() - 1 {
        z_out = Ok(vec![
          i_plus_1.clone(),
          x_i_plus_1.clone(),
          y_i_plus_1.clone(),
        ]);
      }

      // update i, x_i, and y_i for the next iteration
      i = i_plus_1;
      x_i = x_i_plus_1;
      y_i = y_i_plus_1;
    }

    z_out
  }

  fn output(&self, z: &[G::Scalar]) -> Vec<G::Scalar> {
    // sanity check
    debug_assert_eq!(z[0], self.seq[0].i);
    debug_assert_eq!(z[1], self.seq[0].x_i);
    debug_assert_eq!(z[2], self.seq[0].y_i);

    // compute output using advice
    vec![
      self.seq[self.seq.len() - 1].i_plus_1,
      self.seq[self.seq.len() - 1].x_i_plus_1,
      self.seq[self.seq.len() - 1].y_i_plus_1,
    ]
  }
}

pub fn nova_ivc(num_steps: usize, num_iters_per_step: usize, 
  pp: PublicParams<E1, E2, MinRootCircuit<<E1 as Engine>::GE>, TrivialCircuit<<E2 as Engine>::Scalar>>, 
  circuit_secondary: TrivialCircuit<<E2 as Engine>::Scalar>
) -> Duration {

    let start = Instant::now();
    // produce non-deterministic advice
    let (z0_primary, minroot_iterations) = MinRootIteration::<<E1 as Engine>::GE>::new(
      num_iters_per_step * num_steps,
      &<E1 as Engine>::Scalar::zero(),
      &<E1 as Engine>::Scalar::zero(),
      &<E1 as Engine>::Scalar::one(),
    );
    let minroot_circuits = (0..num_steps)
      .map(|i| MinRootCircuit {
        seq: (0..num_iters_per_step)
          .map(|j| MinRootIteration {
            i: minroot_iterations[i * num_iters_per_step + j].i,
            x_i: minroot_iterations[i * num_iters_per_step + j].x_i,
            y_i: minroot_iterations[i * num_iters_per_step + j].y_i,
            i_plus_1: minroot_iterations[i * num_iters_per_step + j].i_plus_1,
            x_i_plus_1: minroot_iterations[i * num_iters_per_step + j].x_i_plus_1,
            y_i_plus_1: minroot_iterations[i * num_iters_per_step + j].y_i_plus_1,
          })
          .collect::<Vec<_>>(),
      })
      .collect::<Vec<_>>();

    let z0_secondary = vec![<E2 as Engine>::Scalar::zero()];

    type C1 = MinRootCircuit<<E1 as Engine>::GE>;
    type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;
    // produce a recursive SNARK
    // println!("Generating a RecursiveSNARK...");
    let mut recursive_snark: RecursiveSNARK<E1, E2, C1, C2> =
      RecursiveSNARK::<E1, E2, C1, C2>::new(
        &pp,
        &minroot_circuits[0],
        &circuit_secondary,
        &z0_primary,
        &z0_secondary,
      )
      .unwrap();

    for (_i, circuit_primary) in minroot_circuits.iter().enumerate() {
      let res = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
      assert!(res.is_ok());
    }
    start.elapsed()
}

#[test]
fn minroot_test() {
    let num_steps = 10;
    let num_iters_per_step = 1;
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

    let exec_time = nova_ivc(num_steps, num_iters_per_step, pp.clone(), circuit_secondary.clone());
    println!("Execution time: {:?}", exec_time);
}