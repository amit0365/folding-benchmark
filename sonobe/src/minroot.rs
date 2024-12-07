//! Demonstrates how to use Nova to produce a recursive proof of the correct execution of
//! iterations of the `MinRoot` function, thereby realizing a Nova-based verifiable delay function (VDF).
//! We execute a configurable number of iterations of the `MinRoot` function per step of Nova's recursion.

use ark_r1cs_std::prelude::AllocationMode;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use num_bigint::BigUint;

use folding_schemes::{
    frontend::FCircuit,
    Error,
};


#[derive(Clone, Debug)]
pub struct MinRootIteration<F: PrimeField> {
  pub i: F,
  pub x_i: F,
  pub y_i: F,
  pub i_plus_1: F,
  pub x_i_plus_1: F,
  pub y_i_plus_1: F,
}

impl<F: PrimeField> MinRootIteration<F> {
  // produces a sample non-deterministic advice, executing one invocation of MinRoot per step
  fn new(num_iters: usize, i_0: &F, x_0: &F, y_0: &F) -> (Vec<F>, Vec<Self>) {
    // exp = (p - 3 / 5), where p is the order of the group
    // x^{exp} mod p provides the fifth root of x
    let exp = {
      let p: BigUint = F::MODULUS.into(); //G::group_params().2.to_biguint().unwrap();
      let two = BigUint::parse_bytes(b"2", 10).unwrap();
      let three = BigUint::parse_bytes(b"3", 10).unwrap();
      let five = BigUint::parse_bytes(b"5", 10).unwrap();
      let five_inv = five.modpow(&(&p - &two), &p);
      (&five_inv * (&p - &three)) % &p
    };

    let mut res = Vec::new();
    let mut i = *i_0;
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

      let y_i_plus_1 = x_i + i;
      let i_plus_1 = i + F::ONE;

      res.push(Self {
        x_i,
        y_i,
        x_i_plus_1,
        y_i_plus_1,
        i,
        i_plus_1,
      });

      x_i = x_i_plus_1;
      y_i = y_i_plus_1;
      i = i_plus_1;
    }

    let z0 = vec![*i_0, *x_0, *y_0];

    (z0, res)
  }
}


#[derive(Clone, Debug)]
pub struct MinRootCircuit<F: PrimeField> {
  pub num_iters_per_step: usize,
  input: Vec<F>,
  pub seq: Vec<MinRootIteration<F>>,
}

impl<F: PrimeField> MinRootCircuit<F> {
    pub fn new(initial_input: Vec<F>, num_iters_per_step: usize) -> Self {
        let (_output, seq) = 
            MinRootIteration::new(num_iters_per_step, &initial_input[0], &initial_input[1], &initial_input[2]);

        Self { 
            num_iters_per_step,
            input: initial_input.clone(),
            seq, 
        }
    }
}

impl<F: PrimeField> FCircuit<F> for MinRootCircuit<F> {

  type Params = (Vec<F>, usize); // initial input and number of iterations per step
  
  fn new(params: Self::Params) -> Self {
    let (_output, seq) = 
    MinRootIteration::new(params.1, &params.0[0], &params.0[1], &params.0[2]);

    Self { 
        num_iters_per_step: params.1,
        input: params.0.clone(),
        seq, 
    }
  }

  fn state_len(&self) -> usize {
      3
  }

  fn step_native(&mut self, _i: usize, _z_i: Vec<F>) -> Result<Vec<F>, Error> {
        // produces a sample non-deterministic advice, executing one invocation of MinRoot per step
        let (_output, seq) = 
        MinRootIteration::new(self.num_iters_per_step, &self.input[0], &self.input[1], &self.input[2]);
  
        self.seq = seq;
  
        // use the provided inputs
        let i_0 = self.input[0];
        let x_0 = self.input[1];
        let y_0 = self.input[2];
        let mut z_out: Vec<F> = Vec::new();
  
        // variables to hold running x_i and y_i
        let mut x_i = x_0;
        let mut y_i = y_0;
        let mut i = i_0;
        for ii in 0..self.seq.len() {
        // non deterministic advice
        let i_plus_1 = self.seq[ii].i_plus_1;
        let x_i_plus_1 = self.seq[ii].x_i_plus_1;
        let y_i_plus_1 = self.seq[ii].y_i_plus_1;
        // check the following conditions hold:
        // (i) x_i_plus_1 = (x_i + y_i)^{1/5}, which can be more easily checked with x_i_plus_1^5 = x_i + y_i
        // (ii) y_i_plus_1 = x_i
        let x_i_plus_1_sq = x_i_plus_1 * x_i_plus_1;
        let x_i_plus_1_quad = x_i_plus_1_sq * x_i_plus_1_sq;
        assert_eq!(x_i_plus_1_quad * x_i_plus_1, x_i + y_i);

        assert_eq!(y_i_plus_1, x_i + i);
        assert_eq!(i_plus_1, i + F::ONE);

        if ii == self.seq.len() - 1 {
            z_out = vec![i_plus_1, x_i_plus_1, y_i_plus_1];
        }
  
            // update i, x_i and y_i for the next iteration
            y_i = y_i_plus_1;
            x_i = x_i_plus_1;
            i = i_plus_1;
        }
  
      Ok(z_out)
  }

  fn generate_step_constraints(
      &self,
      cs: ConstraintSystemRef<F>,
      _i: usize,
      z_i: Vec<FpVar<F>>,
  ) -> Result<Vec<FpVar<F>>, SynthesisError> {
      
    let mut z_out: Result<Vec<FpVar<F>>, SynthesisError> =
      Err(SynthesisError::AssignmentMissing);

    // use the provided inputs
    let i_0 = z_i[0].clone();
    let x_0 = z_i[1].clone();
    let y_0 = z_i[2].clone();

    // variables to hold running x_i and y_i

    let mut x_i = x_0;
    let mut y_i = y_0;
    let mut i = i_0;
    for ii in 0..self.seq.len() {
      // non deterministic advice
      let i_plus_1 = FpVar::new_variable(cs.clone(),
       || Ok(self.seq[ii].i_plus_1), AllocationMode::Witness).unwrap();

      let x_i_plus_1 = FpVar::new_variable(cs.clone(),
       || Ok(self.seq[ii].x_i_plus_1), AllocationMode::Witness).unwrap();
      
      let y_i_plus_1 = FpVar::new_variable(cs.clone(),
       || Ok(self.seq[ii].y_i_plus_1), AllocationMode::Witness).unwrap();
      
      // check the following conditions hold:
      // (i) x_i_plus_1 = (x_i + y_i)^{1/5}, which can be more easily checked with x_i_plus_1^5 = x_i + y_i
      // (ii) y_i_plus_1 = x_i
      // (1) constraints for condition (i) are below
      // (2) constraints for condition (ii) is avoided because we just used x_i wherever y_i_plus_1 is used
      let x_i_plus_1_sq = x_i_plus_1.square()?;
      let x_i_plus_1_quad =
        x_i_plus_1_sq.square()?;

      let x_i_plus_1_fifth: FpVar::<F> = x_i_plus_1_quad * x_i_plus_1.clone();
      x_i_plus_1_fifth.conditional_enforce_equal(&(&x_i + &y_i), &Boolean::<F>::TRUE)?;
      i_plus_1.conditional_enforce_equal(&(i.clone() + F::ONE), &Boolean::<F>::TRUE)?;
      y_i_plus_1.conditional_enforce_equal(&(x_i.clone() + i.clone()), &Boolean::<F>::TRUE)?;

      if ii == self.seq.len() - 1 {
        z_out = Ok(vec![i_plus_1.clone(), x_i_plus_1.clone(), y_i_plus_1.clone()]);
      }

      // update x_i and y_i for the next iteration
      y_i = y_i_plus_1;
      x_i = x_i_plus_1;
      i = i_plus_1;
    }

    z_out
  }
}