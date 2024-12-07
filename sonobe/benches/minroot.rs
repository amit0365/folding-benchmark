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

type NOVA = Nova<
    Projective,
    GVar,
    Projective2,
    GVar2,
    MinRootCircuit<Fr>,
    Pedersen<Projective>,
    Pedersen<Projective2>,
    >;

fn bench_nova_ivc(c: &mut Criterion) {
    let mut primary_circuits = Vec::new();
    let mut pp_vec = Vec::new();
    let initial_state = vec![Fr::from(0_u32), Fr::from(0_u32), Fr::from(1_u32)];
    let num_iters_per_step = vec![1024, 2048, 4096, 8192];
    for num_iters in &num_iters_per_step {
        let circuit_primary = MinRootCircuit::<Fr>::new(vec![Fr::from(0_u32), Fr::from(0_u32), Fr::from(1_u32)], *num_iters);
        let (prover_params, _verifier_params) =
        test_nova_setup::<MinRootCircuit<Fr>>(circuit_primary.clone());
        primary_circuits.push(circuit_primary);
        pp_vec.push(prover_params);
    }

    let num_steps = 10;
    let mut group = c.benchmark_group("NOVA IVC");

    group.sample_size(10);

    let mut folding_scheme_vec = Vec::new();
    let mut results = Vec::new();
    for (i, num_iters) in num_iters_per_step.iter().enumerate() {
        folding_scheme_vec.push(NOVA::init(&pp_vec[i], primary_circuits[i].clone(), initial_state.clone()).unwrap());
        let test_name = format!("entire_process_{}", num_iters);
        group.bench_function(&test_name, |b| {
            b.iter_custom(|_iters| {
              let start = Instant::now();
              for _i in 0..num_steps {
                folding_scheme_vec[i].0.prove_step().unwrap();
            }
              start.elapsed()
            })
        });

        let exec_time = 
        {
            let start = Instant::now();
            for _i in 0..num_steps {
                folding_scheme_vec[i].0.prove_step().unwrap();
            }
            start.elapsed()
        };
        results.push((num_iters, exec_time));
    }

    group.finish();

    let mut file = File::create("../benchmark_results/sonobe_nova_minroot.md").expect("Failed to create file");
    writeln!(file, "| Num Steps  | Num Iters per step | Execution Time (ms) | Primary_circuit_size | Secondary_circuit_size |").expect("Failed to write to file");
    writeln!(file, "|------------|--------------------|---------------------|----------------------|------------------------|").expect("Failed to write to file");
    for (i, (num_iters, duration)) in results.iter().enumerate() {
        writeln!(
            file,
            "| {}         | {}               | {:?} ms             | {:?}                | {:?}                  |",
            num_steps, num_iters, duration.as_millis(), folding_scheme_vec[i].1, folding_scheme_vec[i].2
        ).expect("Failed to write to file");
    }
}

fn minroot_nova(c: &mut Criterion) {
    bench_nova_ivc(c);
}

criterion_group!(benches, minroot_nova);
criterion_main!(benches);