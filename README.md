# uni_arm_sim
This project is used as an template for the Unicorn Engine to simulate an ARM Cortex M processor. 
It includes a C project in the "content" folder which is loaded into the simulation. The framework
mocks a Serial IO peripheral. Additionaly it includes sample codings for Read & Write to the simulated Serial IO peripheral registers.

## Setup / Requirements
* Rust toolchain
* "gcc-arm-none-eabi" compiler toolchain
* make toolchain

## Execution

To compile target project: 

**"/content/make"**

To run simulation

**"cargo run"**
