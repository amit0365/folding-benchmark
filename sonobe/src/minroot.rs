//! Demonstrates how to use Nova to produce a recursive proof of the correct execution of
//! iterations of the `MinRoot` function, thereby realizing a Nova-based verifiable delay function (VDF).
//! We execute a configurable number of iterations of the `MinRoot` function per step of Nova's recursion.

use ark_ec::{CurveGroup, Group};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::fields::fp::{AllocatedFp, FpVar};
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use core::marker::PhantomData;
use std::time::Instant;
use num_bigint::BigUint;

use folding_schemes::commitment::pedersen::Pedersen;
use folding_schemes::folding::nova::Nova;
use folding_schemes::frontend::FCircuit;
use folding_schemes::{Error, FoldingScheme};


#[derive(Clone, Debug)]
pub struct MinRootIteration<G: Group> {
  pub x_i: G::ScalarField,
  pub y_i: G::ScalarField,
  pub x_i_plus_1: G::ScalarField,
  pub y_i_plus_1: G::ScalarField,
}

impl<G: Group> MinRootIteration<G> {
  // produces a sample non-deterministic advice, executing one invocation of MinRoot per step
  fn new(num_iters: usize, x_0: &G::ScalarField, y_0: &G::ScalarField) -> (Vec<G::ScalarField>, Vec<Self>) {
    // exp = (p - 3 / 5), where p is the order of the group
    // x^{exp} mod p provides the fifth root of x
    let exp = {
      let p = G::group_params().2.to_biguint().unwrap();
      let two = BigUint::parse_bytes(b"2", 10).unwrap();
      let three = BigUint::parse_bytes(b"3", 10).unwrap();
      let five = BigUint::parse_bytes(b"5", 10).unwrap();
      let five_inv = five.modpow(&(&p - &two), &p);
      (&five_inv * (&p - &three)) % &p
    };

    let mut res = Vec::new();
    let mut x_i = *x_0;
    let mut y_i = *y_0;
    for _i in 0..num_iters {
      let x_i_plus_1 = (x_i + y_i).pow(&exp.to_u64_digits()); // computes the fifth root of x_i + y_i

      // sanity check
      if cfg!(debug_assertions) {
        let sq = x_i_plus_1 * x_i_plus_1;
        let quad = sq * sq;
        let fifth = quad * x_i_plus_1;
        assert_eq!(fifth, x_i + y_i);
      }

      let y_i_plus_1 = x_i;

      res.push(Self {
        x_i,
        y_i,
        x_i_plus_1,
        y_i_plus_1,
      });

      x_i = x_i_plus_1;
      y_i = y_i_plus_1;
    }

    let z0 = vec![*x_0, *y_0];

    (z0, res)
  }
}


#[derive(Clone, Debug)]
pub struct MinRootCircuit<G: Group> {
  pub seq: Vec<MinRootIteration<G>>,
}

impl<G: Group> FCircuit<G::ScalarField> for MinRootCircuit<G> {

  type Params = ();
  fn new(_params: Self::Params) -> Self {
      Self { seq: Vec::new() }
  }

  fn state_len(&self) -> usize {
      1
  }

  fn step_native(&self, _i: usize, z_i: Vec<G::ScalarField>) -> Result<Vec<G::ScalarField>, Error> {
      Ok(vec![z_i[0] * z_i[0] * z_i[0] + z_i[0] + G::ScalarField::from(5_u32)])
  }

  fn generate_step_constraints(
      &self,
      cs: ConstraintSystemRef<G::ScalarField>,
      _i: usize,
      z_i: Vec<FpVar<G::ScalarField>>,
  ) -> Result<Vec<FpVar<G::ScalarField>>, SynthesisError> {
      let five = FpVar::<G::ScalarField>::new_constant(cs.clone(), G::ScalarField::from(5u32))?;
      let mut z_out: Result<Vec<FpVar<G::ScalarField>>, SynthesisError> =
      Err(SynthesisError::AssignmentMissing);

    // use the provided inputs
    let x_0 = z_i[0].clone();
    let y_0 = z_i[1].clone();

    // variables to hold running x_i and y_i
    let mut x_i = x_0;
    let mut y_i = y_0;
    for i in 0..self.seq.len() {
      // non deterministic advice
      let x_i_plus_1 = FpVar::new_variable(cs.clone(),
       || Ok(self.seq[i].x_i_plus_1), AllocationMode::Constant).unwrap();
      
      // check the following conditions hold:
      // (i) x_i_plus_1 = (x_i + y_i)^{1/5}, which can be more easily checked with x_i_plus_1^5 = x_i + y_i
      // (ii) y_i_plus_1 = x_i
      // (1) constraints for condition (i) are below
      // (2) constraints for condition (ii) is avoided because we just used x_i wherever y_i_plus_1 is used
      let x_i_plus_1_sq = x_i_plus_1.square()?;
      let x_i_plus_1_quad =
        x_i_plus_1_sq.square()?;

      if i == self.seq.len() - 1 {
        z_out = Ok(vec![x_i_plus_1.clone(), x_i.clone()]);
      }

      // update x_i and y_i for the next iteration
      y_i = x_i;
      x_i = x_i_plus_1;
    }

    z_out
  }
}

// pub fn nova_ivc(num_steps: usize, num_iters_per_step: usize, pp: PublicParams<E1, E2, MinRootCircuit<<E1 as Engine>::GE>, TrivialCircuit<<E2 as Engine>::Scalar>>, circuit_secondary: TrivialCircuit<<E2 as Engine>::Scalar>) {
//   println!("Nova-based VDF with MinRoot delay function");
//   println!("=========================================================");

    // produce non-deterministic advice
    // let (z0_primary, minroot_iterations) = MinRootIteration::<<E1 as Engine>::GE>::new(
    //   num_iters_per_step * num_steps,
    //   &<E1 as Engine>::Scalar::zero(),
    //   &<E1 as Engine>::Scalar::one(),
    // );
    // let minroot_circuits = (0..num_steps)
    //   .map(|i| MinRootCircuit {
    //     seq: (0..num_iters_per_step)
    //       .map(|j| MinRootIteration {
    //         x_i: minroot_iterations[i * num_iters_per_step + j].x_i,
    //         y_i: minroot_iterations[i * num_iters_per_step + j].y_i,
    //         x_i_plus_1: minroot_iterations[i * num_iters_per_step + j].x_i_plus_1,
    //         y_i_plus_1: minroot_iterations[i * num_iters_per_step + j].y_i_plus_1,
    //       })
    //       .collect::<Vec<_>>(),
    //   })
    //   .collect::<Vec<_>>();

    // let z0_secondary = vec![<E2 as Engine>::Scalar::zero()];

    // type C1 = MinRootCircuit<<E1 as Engine>::GE>;
    // type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;
    // // produce a recursive SNARK
    // // println!("Generating a RecursiveSNARK...");
    // let mut recursive_snark: RecursiveSNARK<E1, E2, C1, C2> =
    //   RecursiveSNARK::<E1, E2, C1, C2>::new(
    //     &pp,
    //     &minroot_circuits[0],
    //     &circuit_secondary,
    //     &z0_primary,
    //     &z0_secondary,
    //   )
    //   .unwrap();

    // for (i, circuit_primary) in minroot_circuits.iter().enumerate() {
    //   let res = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
    //   assert!(res.is_ok());
    // }

//}