//|============================================================================|
//|                                TOP OF FILE                                 |
//|----------------------------------------------------------------------------|
//|                                                                            |
//|     ExecutableMachine_simple.sol                [Solidity source file]     |
//|                                                                            |
//|                                                                            |
//|         Description:                                                       |
//|         ============                                                       |
//|                                                                            |
//|             This file constitutes source code in the Solidity              |
//|             language for a smart contract Exec[G] implementing             |
//|             an executable interpreter for a (hard-coded) sample            |
//|             garbled state machine G.                                       |
//|                                                                            |
//|             The machine G in this case is a simplified 4-state             |
//|             version of the supply-chain demo shown in Fig. 6 of            |
//|             Cordi et al., "Auditable, Available and Resilient              |
//|             Private Computation on the Blockchain via MPC," to             |
//|             be presented at CSCML 2022.                                    |
//|                                                                            |
//|             The JSON source file that represented the original             |
//|             finite state machine F (before garbling) was:                  |
//|                                                                            |
//|                     [["S1w", {"V1": "R"}, "S1h"],                          |
//|                      ["S1h", {"V1": "T"}, "S2w"],                          |
//|                      ["S2w", {"V2": "R"}, "S2h"]]                          |
//|                                                                            |
//|             This demo exercised our ability to store the                   |
//|             machine's garbled arc data in a separate storage               |
//|             contract, which is deployed separately from the                |
//|             main executor contract.  This approach allows for              |
//|             much larger state machines to be represented.                  |
//|                                                                            |
//|                                                                            |
//|         Language:     Solidity, ver. 0.5.0                                 |
//|                                                                            |
//|                                                                            |
//|         Defined names:   (Top-level names defined in this file.)           |
//|         ==============                                                     |
//|                                                                            |
//|             Storage [contract]                                             |
//|                                                                            |
//|                 This contract provides the garbled arc data.               |
//|                 It is queried by the main executor contract.               |
//|                                                                            |
//|             ExecutableMachine [contract]                                   |
//|                                                                            |
//|                 The main smart contract Exec[G] implementing               |
//|                 an executable version of garbled machine G.                |
//|                 (The actual garbled machine data is kept in                |
//|                 the separate Storage contract, however.)                   |
//|                                                                            |
//|                                                                            |
//|         External interface:     (Intended for outside use.)                |
//|         ===================                                                |
//|                                                                            |
//|             ExecutableMachine.curState() - This getter function            |
//|                 retrieves the (coded) current state of the garbled         |
//|                 state machine G.                                           |
//|                                                                            |
//|             ExecutableMachine.nextStep() - Returns the index of            |
//|                 the next time step to be executed. (Initially 0.)          |
//|                                                                            |
//|             ExecutableMachine.provideInput() - Provide a (coded)           |
//|                 value for an input variable for the next time step.        |
//|                                                                            |
//|                                                                            |
//|         Internal interface:     (Not intended for outside use.)            |
//|         ===================                                                |
//|                                                                            |
//|             Storage.getArc() - Returns the garbled arc data for a          |
//|                 particular time step.                                      |
//|                                                                            |
//|                                                                            |
//|         Revision history:                                                  |
//|         =================                                                  |
//|             All revisions are by MPF (M.P. Frank, mpfrank@sandia.gov),     |
//|             and RK (R. Kao, rkao@sandia.gov) w. contributions from         |
//|             CNC (C.N. Cordi, cncordi@sandia.gov).                          |
//|                                                                            |
//|             v0.0 (2018-08-16) - First checkin; not yet compiled.           |
//|             v0.1 (2018-08-22) - Compiles in Truffle.                       |
//|             v0.2 (2018-09-01) - Last version before debugging.             |
//|             v0.3 (2018-10-08) - A few bug fixes; switched hash             |
//|                 function from sha256() (256-bit SHA-2) to keccak256()      |
//|                 (which is NOT the standard SHA-3 function).                |
//|             v0.4 (2019-02-19) - New version for supply-chain demo.         |
//|             v1.0 (2022-03-18) - Cleaned up comments for release.           |
//|                                                                            |
//|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

pragma solidity 0.5.0;     // Need to figure out the right version specifier still


    //|========================================================================|
    //|                                                                        |
    //|     Storage                                             [contract]     |
    //|                                                                        |
    //|         The Storage contract stores the garbled arc data for           |
    //|         the finite state machine.                                      |
    //|                                                                        |
    //|                                                                        |
    //|     Public interface:   (Methods callable from other contracts.)       |
    //|     =================                                                  |
    //|                                                                        |
    //|         getArc(timestep) - Given a time-step index, returns two        |
    //|             memory arrays representing the next-state and valid        |
    //|             fields of the garbled arc data.                            |
    //|                                                                        |
    //|                                                                        |
    //|     Internal types:     (Not intended to be externally used.)          |
    //|     ===============                                                    |
    //|                                                                        |
    //|         struct EncryptedArc - Stores encrypted data for one arc        |
    //|             of the garbled state machine.                              |
    //|                                                                        |
    //|                                                                        |
    //|     Internal constants:                                                |
    //|     ===================                                                |
    //|                                                                        |
    //|         uint16 maxSteps - Maximum # of supported time-steps.           |
    //|                                                                        |
    //|         uint16 nArcs - How many state-transition arcs machine has.     |
    //|                                                                        |
    //|         EncryptedArc[][] arcs - Garbled array of arcs by time step.    |
    //|                                                                        |
    //|                                                                        |
    //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

contract Storage {

    //|====================================================================|
    //| Structure type definitions.                     [contract section] |
    //|                                                                    |
    //|     These are lexically defined locally within the contract,       |
    //|     so they're effectively private.                                |
    //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

        // Private struct type for representing garbled state-machine arcs.

    struct EncryptedArc {
        uint256 encNext;    // The arc's encrypted 'next state' entry.
        uint256 encValid;   // The arc's encrypted 'valid' entry.
    }

    //|====================================================================|
    //| State variables & constants.                    [contract section] |
    //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

        // In this simple machine, we allow stepping through just the first
        // three steps of the supply-chain demo.

    uint16 constant maxSteps = 3;

        // Number of arcs (per step) in the machine, q (0 <= q <= 65,535).

    uint16 constant nArcs = 3;       // In this demo, the FSM has only 3 arcs.

        // Encrypted representations of all FSM arcs for all time steps.

    EncryptedArc[nArcs][maxSteps] public arcs;
        // Initialized in constructor, below.


    //|====================================================================|
    //| Contract constructor.                           [contract section] |
    //|                                                                    |
    //|     This initializes the smart contract when it is created.        |
    //|     (Everything that can't be initialized with a literal           |
    //|     initializer goes here, and initializing arrays of structs      |
    //|     inline doesn't seem to work.)  This particular garbled         |
    //|     representation G of the FSM F was generated by the sample      |
    //|     script garbler.py using the random seed "xyz".                 |
    //|                                                                    |
    //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

    constructor() public  {     // Constructor for storage contract.

            //|==============================================================
            //| The actual "logic" of the garbled state machine is here.
            //| For each time step, for each arc index, we have an encrypted
            //| arc representation.  The order of the arcs at each time step
            //| is random, and the encrypted data looks fully random to
            //| anyone not holding the input keys.  Thus, this machine's
            //| function is fully obfuscated, to the level of only knowing an
            //| upper bound on its size parameters (e.g., its maximum number
            //| of time steps, and maximum number of state-machine arcs).

        // **********************************************************************
        // *** THE FOLLOWING CODE WAS AUTOMATICALLY GENERATED BY THE GARBLER: ***
        // *** (Should be placed in the constructor for the machine contract) ***

        arcs[0][0] = EncryptedArc(
            0x8a4acdf6623eb3395b04b959e5f66815b0b17a643216e4ccc8d6a1e0258065eb,
            0x3f93525d9836199fb4fc6e0007e240697dccfc6ca6dec0199fd516d321c12604);
        arcs[0][1] = EncryptedArc(
            0x6d1cf0fc2bc221e86b0c5aedeb26879b1e7e5cfcd639783cb22f61e16a0e3f0f,
            0xbabc20a03383c12feb111fc02ccf83d94b68e25e3fbbd1e76deffc8e84d94e37);
        arcs[0][2] = EncryptedArc(
            0x5bfe6f8df68e77f65f0455191a5e2d182fb5ff2a17912d6e2bd7e1f90f38229d,
            0x8cbe0122ae01f811a4b8e5c0b6105ff832dde3c8dc34d0ad955dbb956214753b);

        arcs[1][0] = EncryptedArc(
            0x72c0959ea1c2ed52811ca03d7752ac1f9ed321eba87d148af0cc13390eb21462,
            0x477f07ff53e5b08d5d3f8eb594cd8da402378728ba1aa8aa49338d11f7502be1);
        arcs[1][1] = EncryptedArc(
            0x407e0179552f3db97a49eea9420f3ee62791981d5e28570c0661c37849074615,
            0x71be10f4c59e0f8ba6ef17825b729db8f78b7130b437a0b3438201c825038f34);
        arcs[1][2] = EncryptedArc(
            0x4bbb84f9a1a9002ce82036a9e62e91b5bedac7d23de719a58b921532d99699d2,
            0x35959d7f79e9c09ce798f6c66b2fffd9f6885ea53e74d858bc3e7f7fa1654ac3);

        arcs[2][0] = EncryptedArc(
            0xff854c03c0e28cfe31844c4bfd076558566c41a7cf7388d293266584a411c3e8,
            0xbb4e6f948eb37df2466c11bf8e7b759680adb80d695d74614e27f1b7bf2372de);
        arcs[2][1] = EncryptedArc(
            0xd726138ba7d8f135cf9d0a540ad4eee6bace24c6a87f2649975715bd76e2a0f4,
            0xc4e8634fe430851c781014d47e6ec2b7401615f7c36d85d4adb43f5e0b3b864b);
        arcs[2][2] = EncryptedArc(
            0x8d3c82efa18e5de5a65a840b529ff2b37938ba18886d6d1b20d43c444893086f,
            0x9c17826bb719d9d31237ad54c4eb67dc6ce367f9efea7665e27b8752aedfa5ab);

    }

        // This method takes the argument <timestep> and returns arrays
        // containing all of the encrypted encNext and encValid values
        // for the arcs of that timestep.

    function getArc(uint16 timestep) public view returns(uint256[] memory, uint256[] memory) {

            // Declare arrays to hold the result data.

        uint256[] memory encNext = new uint256[](arcs[timestep].length);
        uint256[] memory encValid = new uint256[](arcs[timestep].length);

            // Copy the arc data for the selected timestep to the result arrays.

        for (uint16 i = 0; i < arcs[timestep].length; i++) {
            encNext[i] = arcs[timestep][i].encNext;
            encValid[i] = arcs[timestep][i].encValid;
        }

            // Return the data to the calling contract.

        return (encNext, encValid);
    }
}


    //|========================================================================|
    //|                                                                        |
    //|     ExecutableMachine                                   [contract]     |
    //|                                                                        |
    //|         The ExecutableMachine contract is the main smart               |
    //|         contract making up the implementation Exec[G] of an            |
    //|         executable garbled state machine G.  In this imple-            |
    //|         mentation, the actual garbled machine data for G is            |
    //|         kept in a separate storage contract, above.                    |
    //|                                                                        |
    //|         The constructor for this contract accepts a list of            |
    //|         storage contract addresses, although in this example,          |
    //|         we only use a single storage contract.  (More can be           |
    //|         used, allowing us to implement much larger machines.)          |
    //|                                                                        |
    //|                                                                        |
    //|     Public interface:                                                  |
    //|     =================                                                  |
    //|                                                                        |
    //|         curState() - This getter function returns the coded            |
    //|             current state of the garbled state machine G.              |
    //|                                                                        |
    //|         nextStep() - This getter function returns the time             |
    //|             step number of the next time step to be executed.          |
    //|             That is, it's the time step that we are currently          |
    //|             gathering the inputs to. (Starts at 0.)                    |
    //|                                                                        |
    //|         provideInput(value) - Provide a (coded) value                  |
    //|             for a specified input variable for this time step.         |
    //|                                                                        |
    //|                                                                        |
    //|     Private interface:  (Only the contract owner may invoke.)          |
    //|     ==================                                                 |
    //|                                                                        |
    //|         resetContract() - Reset the machine to its initial             |
    //|             state so that it may be re-executed.  NOTE: It             |
    //|             is not recommended to permit re-execution for              |
    //|             secure applications, as this can weaken the                |
    //|             privacy properties of the system.                          |
    //|                                                                        |
    //|                                                                        |
    //|     Internal types:     (Not intended to be externally used.)          |
    //|     ===============                                                    |
    //|                                                                        |
    //|         struct EncryptedArc - Stores encrypted data for one arc        |
    //|             of the garbled state machine.                              |
    //|                                                                        |
    //|                                                                        |
    //|     Internal constants:                                                |
    //|     ===================                                                |
    //|                                                                        |
    //|         uint16 maxSteps - Maximum # of supported time-steps.           |
    //|                                                                        |
    //|         uint16 nArcs - How many state-transition arcs machine has.     |
    //|                                                                        |
    //|         uint256 sInit - Coded rep. of initial state of machine.        |
    //|                                                                        |
    //|                                                                        |
    //|     Internal variables:                                                |
    //|     ===================                                                |
    //|                                                                        |
    //|         uint16 nextStep - Sequential index of current time step.       |
    //|                                                                        |
    //|         uint256 curState - Coded current state of machine;             |
    //|             externally readable via the .curState() getter             |
    //|             function.                                                  |
    //|                                                                        |
    //|         uint256 combinedInputs - Represents the full set of            |
    //|             all input values received so far on this time step.        |
    //|                                                                        |
    //|                                                                        |
    //|     Internal functions:                                                |
    //|     ===================                                                |
    //|                                                                        |
    //|         getArc(addr,timestep) - Retrieve the arc data for              |
    //|             the given timestep from the given storage                  |
    //|             contract address.                                          |
    //|                                                                        |
    //|         executeStep() - Execute a step of the garbled state            |
    //|             machine, given the input values provided so far.           |
    //|                                                                        |
    //|         endecrypt(entryID,data) - Encrypt the given data               |
    //|             block for storage under entry identifier entryID,          |
    //|             or decrypt it if already encrypted.                        |
    //|                                                                        |
    //|         hash(value) - Return a cryptographic hash of the given         |
    //|             data value.                                                |
    //|                                                                        |
    //|                                                                        |
    //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

/// @title Executable garbled state machine.
contract ExecutableMachine {

    //|====================================================================|
    //| Structure type definitions.                  [contract section]    |
    //|                                                                    |
    //|     These are lexically defined locally within the contract,       |
    //|     so they're effectively private.                                |
    //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

        // Declare event types for diagnostic output.

    event Message (
        string _msg
    );

    event Value (
        uint256 _value
    );

        // Private struct type for representing garbled state-machine arcs.
        // This struct stores encrypted data for a given arc in the machine.

    struct EncryptedArc {
        uint256 encNext;    // The arc's encrypted 'next state' entry.
        uint256 encValid;   // The arc's encrypted 'valid' entry.
    }


    //|====================================================================|
    //| State variables & constants.                    [contract section] |
    //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

        //|---------------------------------------------------------------------
        //| State variables that are intended as constants (not changing
        //| during execution, but that are not declared as constant because
        //| they're initialized in the contract's constructor.
        //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

        // Upon deployment, an array of addresses of storage contracts can be
        // passed in, allowing for very large machines to be represented.

    address[] storageAddress;

    address owner;      // Records the address of the deployer of the contract.

        // Coded initial-state representation, 256 bits (32 bytes).

    uint256 sInit;


        //|---------------------------------------------------------------------
        //| The following state variables are not constant, but correspond
        //| to actual variable components of the machine state.
        //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

        // Coded representation of current state, 256 bits (32 bytes).
        // It's initialized to the machine's initial state in the constructor.
        // NOTE: We mark 'curState' as 'public' because its getter is the only
        // 'sanctioned' means at present of obtaining output from the machine.

    uint256 public curState;


        //|---------------------------------------------------------------------
        //| Constants of the machine definition.  We hard-code these
        //| values as appropriate for the specific garbled state machine
        //| G that we are representing.
        //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

        // Maximum number of supported time-steps of state- machine
        // execution, L (1 <= L <= 65,535).

    uint16 constant maxSteps = 3;
        // In this simple machine, we allow stepping through just the first
        // three steps of the supply-chain demo.

        // Number of arcs (per step) in the machine, q (0 <= q <= 65,535).

    uint16 constant nArcs = 3;       // In this demo, the FSM has only 3 arcs.


        //|---------------------------------------------------------------------
        //| More state variables. (Should really move this next to curState.)
        //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

        // Next time step number to be executed, in range 0 to maxSteps.
        // If it ever gets to maxSteps, the machine halts at that point.
        // Note: nextStep is public so input providers can synchronize.

    uint16 public nextStep = 0;    // The first time step to be executed is step #0.


            //|--------------------------------------------------------------
            //| The following state variables are used for implementing the
            //| simple "single-shot" input model.

        // All of the input values received so far, combined associatively.
    uint256 combinedInputs = 0;      // Zero at the start of each step.


    //|====================================================================|
    //| Contract constructor.                           [contract section] |
    //|                                                                    |
    //|     This initializes the smart contract when it is created.        |
    //|     (Everything that can't be initialized with a literal           |
    //|     initializer goes here, and initializing arrays of structs      |
    //|     inline doesn't seem to work.)  This particular garbled         |
    //|     representation G of the FSM F was generated by the sample      |
    //|     script garbler.py using the random seed "xyz".                 |
    //|                                                                    |
    //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

    constructor(address[] memory _a) public {

            // Remember the addresses of our storage contracts,
            // and of this contract's creator.

        for (uint16 i = 0; i < _a.length; i++) {
            storageAddress.push(_a[i]);
        }

        owner = msg.sender;

            // Initialize the garbled initial state constant.

        sInit = 0x5c8b28ab72dfec5dd643f8d9eaf9d841f6bc36176fa3353e87a737438e3be1fe;

            // Initialize the current-state variable to the initial state.

        curState = sInit;

    }


    //|====================================================================|
    //| Public (and external) functions.                [contract section] |
    //|                                                                    |
    //|     These constitute the visible external interface to the         |
    //|     smart contract, once it's been created.                        |
    //|                                                                    |
    //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

        // This allows resetting the state of the contract, to allow
        // for repeated testing. A real application would likely not
        // provide this functionality, as repeated execution weakens
        // the privacy properties of the system.

    function resetContract() public {
        require(msg.sender == owner);
        curState = sInit;
        nextStep = 0;
        combinedInputs = 0;
    }

        //|----------------------------------------------------------------|
        //|                                                                |
        //|     provideInput()                      [public function]      |
        //|                                                                |
        //|         This public function may be called externally          |
        //|         by input providers to supply a specific coded          |
        //|         input value v to a specific input variable V           |
        //|         for the current time step.  Currently, the             |
        //|         input provider is not authenticated.                   |
        //|                                                                |
        //|         This version of provideInput() performs                |
        //|         single-shot updating: That is, it updates              |
        //|         the machine state after each input.                    |
        //|                                                                |
        //|     Arguments:                                                 |
        //|                                                                |
        //|         uint256 value - The 256-bit encrypted value            |
        //|             (key) of the provided value v of the pro-          |
        //|             vided variable V for the current time-step.        |
        //|                                                                |
        //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

    /** @dev Provide a value for an input variable for this time step.
      * @param value The 256-bit coded representation of the value being provided.
      */
    function provideInput(uint256 value) public returns (bool updated) {

        emit Message("Inside provideInput().");

            // Merge the new input value in with the ones already received
            // for this time step.

        combinedInputs ^= value;

        emit Message("combinedInputs is:");
        emit Value(combinedInputs);

            // This version of provideInput() supports single-shot updating:
            // That is, it checks to see if there is a matching arc after each
            // input that's been received, and if so it updates the state.

        updated = executeStep();
            // Attempt to update the state based on info received.

        emit Message("About to leave provideInput().");

    } // End function ExecutableMachine.provideInput().


    //|================================================================|
    //| Private/internal functions.                 [contract section] |
    //|                                                                |
    //|     These can only be called from within the present           |
    //|     contract, or (in the case of internal functions)           |
    //|     from within derived contracts.                             |
    //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

        // This one just dispatches to a given storage contract to retrieve
        // the arc data for the current time step.

    function getArc(address addr, uint16 timestep) private view returns (uint256[] memory, uint256[] memory) {
        Storage s = Storage(addr);
        return s.getArc(timestep);
    }

        //|----------------------------------------------------------------|
        //|                                                                |
        //|     executeStep()                       [private function]     |
        //|                                                                |
        //|         This private function is called internally from        |
        //|         provideInput() to attempt actually updating the        |
        //|         current machine state based on inputs provided.        |
        //|                                                                |
        //|     Error handling:                                            |
        //|                                                                |
        //|         If no more steps are supported, this function has      |
        //|         no effect.                                             |
        //|                                                                |
        //|         If none of the encrypted arcs for the current          |
        //|         time step match the set of provided input values,      |
        //|         then this function has no effect.                      |
        //|                                                                |
        //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

    /** @dev Attempt to carry out the next execution step of the machine.
      */
    function executeStep() private returns (bool updated) {

        emit Message("Inside executeStep().");

            // This local boolean just keeps track of whether the
            // current state was actually updated yet.

        updated = false;    // Initially no.

            // If we've already executed the max number of steps,
            // do nothing and return that the state wasn't updated.

        if (nextStep >= maxSteps) {
            return updated;       // No more execution steps are supported.
        }

            // Construct the arc identifier, by combining the (garbled)
            // current state ID with the combined input keys.

        uint256 arcID = curState ^ combinedInputs;

            // Construct the entry identifiers for the 'next-state' and
            // 'valid' entries from the arc identifier by combining it
            // with some arbitrary constants.

        uint256 nextID = arcID ^ (uint256(bytes32('n')) >> 248);
        uint256 validID = arcID ^ (uint256(bytes32('v')) >> 248);
            // NOTE: The '>>248' above is necessary to move the nonzero byte
            // representing 'n' or 'v' from the MSB to the LSB position, for
            // compatibility with our garbler.py code.

            // Search for the arc whose encrypted 'valid' entry is 0.

        bool foundIt = false;
        uint16 arcIndex;
        uint256[] memory encNext;
        uint256[] memory encValid;
        (encNext, encValid) = getArc(storageAddress[0], nextStep);
        for (arcIndex = 0; arcIndex < nArcs; arcIndex++) {
            uint256 valid = endecrypt(validID, encValid[arcIndex]);
            if (valid == 0) {   // All 0's is our code meaning "this is the right arc"
                foundIt = true;
                break;
            }
        }

            // If we didn't find it, then return (don't update the state).

        if (!foundIt) {
            emit Message("Didn't find a match.");
            return updated;
        }

            // If we found it, then decrypt the next state, and update our state.

        curState = endecrypt(nextID, encNext[arcIndex]);
        nextStep++;

            // Reset input-collection variables, since inputs have been consumed.

        combinedInputs = 0;

        updated = true;
        emit Message("Found a match.");
        return updated;

    } // End function ExecutableMachine.executeStep().


        //|------------------------------------------------------------|
        //|                                                            |
        //|     endecrypt()                [private pure function]     |
        //|                                                            |
        //|         This private function, called internally           |
        //|         by executeStep(), uses a 256-bit key to            |
        //|         encrypt (or decrypt, if already encrypted)         |
        //|         a 256-bit data entry.  It works similarly          |
        //|         to a one-time pad, by XOR'ing the data             |
        //|         with a 'random' pad that is computed as            |
        //|         the hash of the key.  Unless the full key          |
        //|         is known, the result will appear                   |
        //|         completely random.  This encryption method         |
        //|         is unbreakable given standard assumptions          |
        //|         about the security properties of                   |
        //|         cryptographic hash functions.                      |
        //|                                                            |
        //|     Arguments:                                             |
        //|                                                            |
        //|         uint256 entryID - This 256-bit value               |
        //|             identifies a specific data entry to be         |
        //|             encrypted or decrypted; this value is          |
        //|             used as the encryption/decryption key          |
        //|             for the data entry.  "If you can name          |
        //|             it, you can access it" is the idea.            |
        //|                                                            |
        //|         uint256 data - This 256-bit value is the           |
        //|             (plaintext or encrypted) entry data to         |
        //|             be encrypted or decrypted, respectively.       |
        //|                                                            |
        //|     Return value:                                          |
        //|                                                            |
        //|         uint256 res - The 256-bit result of the            |
        //|             encryption or decryption of the data.          |
        //|                                                            |
        //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

    /** @dev Encrypt/decrypt a data value keyed by a given entry identifier.
      * @param entryID The entry identifier, which is a 256-bit derived key.
      * @param data The data to be encrypted or (if already encrypted) decrypted.
      * @param res Result of the encryption/decryption.
      */
    function endecrypt(uint256 entryID, uint256 data) private pure returns (uint256 res) {
        res = hash(entryID) ^ data;      // This is like a one-time pad of the data.
    } // End function ExecutableMachine.endecrypt().


        //|------------------------------------------------------------|
        //|                                                            |
        //|     hash()                     [private pure function]     |
        //|                                                            |
        //|         This private function is called internally         |
        //|         from within endecrypt() to compute a 256-bit       |
        //|         cryptographic hash of a 256-bit data value.        |
        //|         Any suitable hash function could be used,          |
        //|         but we use keccak256() for the time being.         |
        //|                                                            |
        //|     Argument:                                              |
        //|                                                            |
        //|         uint256 value - A 256-bit data value to            |
        //|                             be hashed.                     |
        //|                                                            |
        //|     Return value:                                          |
        //|                                                            |
        //|         uint256 h - The 256-bit hash of the data.          |
        //|                                                            |
        //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

    /** @dev Hash function to be used in this program.
      * @param value 256-bit value to be hashed.
      * @return h The 256-bit hash of that value.
      */
    function hash(uint256 value) private pure returns (uint256 h) {
        h = uint256(keccak256(abi.encodePacked(value)));
                 // ^^^^^^^^^ sha256 (256-bit SHA-2) is another available option.
    } // End function ExecutableMachine.hash().


} // End contract ExecutableMachine.

//|^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^|
//|                END OF FILE:  ExecutableMachine_simple.sol                  |
//|============================================================================|