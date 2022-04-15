//|============================================================================|
//|                                TOP OF FILE                                 |
//|----------------------------------------------------------------------------|
//|                                                                            |
//|     ExecutableMachine_MPA.sol                   [Solidity source file]     |
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
//|             The machine in this case implements a bit-serial               |
//|             protocol for a 2-party, 16-bit multi-party auction,            |
//|             as discussed in Fig. 4 of Cordi et al., "Auditable,            |
//|             Available and Resilient Private Computation on the             |
//|             Blockchain via MPC," to be presented at CSCML 2022.            |
//|                                                                            |
//|             The JSON source file that represented the original             |
//|             finite state machine F (before garbling) was:                  |
//|                                                                            |
//|                 [["S11", {"B1": "0", "B2": "0"}, "S11"],                   |
//|                  ["S11", {"B1": "0", "B2": "1"}, "S01"],                   |
//|                  ["S11", {"B1": "1", "B2": "0"}, "S10"],                   |
//|                  ["S11", {"B1": "1", "B2": "1"}, "S11"],                   |
//|                  ["S10", {"B1": "0", "B2": "0"}, "S10"],                   |
//|                  ["S10", {"B1": "0", "B2": "1"}, "S10"],                   |
//|                  ["S10", {"B1": "1", "B2": "0"}, "S10"],                   |
//|                  ["S10", {"B1": "1", "B2": "1"}, "S10"],                   |
//|                  ["S01", {"B1": "0", "B2": "0"}, "S01"],                   |
//|                  ["S01", {"B1": "0", "B2": "1"}, "S01"],                   |
//|                  ["S01", {"B1": "1", "B2": "0"}, "S01"],                   |
//|                  ["S01", {"B1": "1", "B2": "1"}, "S01"]]                   |
//|                                                                            |
//|             Here, B1 and B2 represent bits of input from the               |
//|             two bidders, which are supplied MSB first.  The                |
//|             state S11 is a state in which neither bidder has               |
//|             been eliminated yet.  The state S10 is a state                 |
//|             where bidder 2 has been eliminated.  And the state             |
//|             S01 is a state where bidder 1 has been eliminated.             |
//|                                                                            |
//|             The input method used here authenticates input                 |
//|             providers, and invokes a special input provider                |
//|             called "unlocker" which activates input codes by               |
//|             "decrypting" them using a separate key. This is                |
//|             a measure taken to prevent lookahead by providers.             |
//|                                                                            |
//|             NOTE: The protocol here could be optimized some-               |
//|             what by combining input values prior to unlocking              |
//|             them, and then unlocking the combined value all                |
//|             at once, after all the inputs for the current                  |
//|             time step have been provided.                                  |
//|                                                                            |
//|             WARNING: Presently, unlockers are effectively un-              |
//|             authenticated.  Almost any Ethereum account could              |
//|             send this contract an invalid unlock message,                  |
//|             which would interfere with the protocol.                       |
//|                                                                            |
//|             NOTE: The algorithm used here reveals (an upper                |
//|             bound on) the number of participants.                          |
//|                                                                            |
//|                                                                            |
//|         Language:     Solidity, ver. 0.5.0                                 |
//|                                                                            |
//|                                                                            |
//|         Defined names:   (Top-level names defined in this file.)           |
//|         ==============                                                     |
//|                                                                            |
//|             ExecutableMachine [contract]                                   |
//|                                                                            |
//|                 The main smart contract Exec[G] implementing               |
//|                 an executable version of garbled machine G.                |
//|                                                                            |
//|                                                                            |
//|         External interface:     (Intended for outside use.)                |
//|         ===================                                                |
//|                                                                            |
//|             ExecutableMachine.curState() - This getter function            |
//|                 retrieves the (coded) current state of the garbled         |
//|                 state machine G.                                           |
//|                                                                            |
//|             ExecutableMachine.nextStep() - This getter function            |
//|                 returns the index of the next time step to be              |
//|                 executed. (Initially 0.)                                   |
//|                                                                            |
//|             ExecutableMachine.provideInput() - Provide a (coded)           |
//|                 value for an input variable for this time step.            |
//|                                                                            |
//|             ExecutableMachine.getInput() - Retrieve a (coded)              |
//|                 input value previously provided to the contract            |
//|                 for the current time step. (This is intended for           |
//|                 use by Unlockers, which are trusted participants           |
//|                 that increase the protocol's privacy properties.)          |
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
//|             v0.5 (2020-06-09) - Changes for multi-party auction demo.      |
//|             v1.0 (2022-03-19) - Cleaned up comments for release.           |
//|                                                                            |
//|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

pragma solidity 0.5.0;     // Need to figure out the right version specifier still


    //|========================================================================|
    //|                                                                        |
    //|     ExecutableMachine                                   [contract]     |
    //|                                                                        |
    //|         The ExecutableMachine contract is the main smart               |
    //|         contract making up the implementation Exec[G] of an            |
    //|         executable garbled state machine G.  In this imple-            |
    //|         mentation, the garbled machine data for G is hard-             |
    //|         coded in this contract's constructor, rather than              |
    //|         residing in a separate storage contract.                       |
    //|                                                                        |
    //|         The input protocol used here requires each input to            |
    //|         be processed by an extra participant called "unlocker"         |
    //|         before it can be utilized.  We assume unlockers do not         |
    //|         collude with other input providers.                            |
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
    //|             gathering the inputs to. Starts at 0.                      |
    //|                                                                        |
    //|         provideInput(value, timeStep, playerID) - Provide a            |
    //|             (coded) <value> on the input line corresponding to         |
    //|             a given participant (identified by <playerID>)             |
    //|             on the given time step. The playerID must be in            |
    //|             the range [0, 255]. Player #0 is the unlocker.             |
    //|                                                                        |
    //|         getInput(providerID) - Retrieve the coded input                |
    //|             previously sent to the contract by input provider          |
    //|             designated with the given providerID, which is an          |
    //|             integer in the range [1, 255]. (In this particular         |
    //|             2-bidder example, it should be either 1 or 2.)             |
    //|                                                                        |
    //|                                                                        |
    //|     Internal types:     (Not intended to be externally used.)          |
    //|     ===============                                                    |
    //|                                                                        |
    //|         struct EncryptedArc - Stores encrypted data for one arc        |
    //|             of the garbled state machine.                              |
    //|                                                                        |
    //|                                                                        |
    //|     Internal constants: (Some aren't actually declared constant):      |
    //|     ===================                                                |
    //|                                                                        |
    //|         uint16 maxSteps - Maximum # of supported time-steps.           |
    //|                                                                        |
    //|         uint16 nArcs - How many state-transition arcs machine has.     |
    //|                                                                        |
    //|         uint256 sInit - Coded rep. of initial state of machine.        |
    //|                                                                        |
    //|         EncryptedArc[][] arcs - Garbled array of arcs by time step.    |
    //|                                                                        |
    //|                                                                        |
    //|                                                                        |
    //|                                                                        |
    //|     Internal variables:                                                |
    //|     ===================                                                |
    //|                                                                        |
    //|         uint16 nextStep - Sequential index of current time step.       |
    //|             Readable with the .nextStep() getter function.             |
    //|                                                                        |
    //|         uint256 curState - Coded current state of machine;             |
    //|             externally readable via the .curState() getter             |
    //|             function.                                                  |
    //|                                                                        |
    //|         uint256[] inputs - Array of coded values of input              |
    //|             variables received so far for this time step.              |
    //|                                                                        |
    //|         uint256 combinedInputs - Represents the full set of            |
    //|             all unlocked (activated) input values received             |
    //|             so far on this time step.                                  |
    //|                                                                        |
    //|                                                                        |
    //|     Internal functions:                                                |
    //|     ===================                                                |
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
        //| Constants of the machine definition.  We hard-code these
        //| values as appropriate for the specific garbled state machine
        //| G that we are representing.
        //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

        // Maximum number of supported time-steps of state- machine
        // execution, L (1 <= L <= 65,535).

    uint16 constant maxSteps = 16;
        // In this demo, two bidders provide consecutive bits of their 16-bit bids
        // over 16 time steps. (Both bidders must provide input in order to advance.)

        // Number of arcs (per step) in the machine, q (0 <= q <= 65,535).
    uint16 constant nArcs = 12;
        // This machine has 12 arcs (3 states with 4 outgoing arcs each).

        // Number of bidders in the auction. The protocol here can easily
        // be extended to support additional bidders (albeit with changes
        // required to the garbled state machine as well).

    uint8 constant numBidders = 2;


        //|---------------------------------------------------------------------
        //| The following are state variables, although some of them are
        //| effectively constant because they're only modified once, during
        //| the contract constructor.
        //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

        // Array to hold garbled inputs provided by each bidder so far for the
        // current time step.  This information is accessed by the unlocker using
        // the getInput() method.

    uint256[numBidders] inputs;

        // Coded initial-state representation, 256 bits (32 bytes).

    uint256 sInit;          // Initialized in constructor (with rest of machine).

        // Encrypted representations of all FSM arcs for all time steps.

    EncryptedArc[nArcs][maxSteps] arcs;
        // Initialized in constructor, below.

        // Next time step number to be executed, in range 0 to maxSteps.
        // If it ever gets to maxSteps, the machine halts at that point.
        // Note: nextStep is public so input providers can synchronize.

    uint16 public nextStep = 0;    // The first time step to be executed is step #0.

        // Coded representation of current state, 256 bits (32 bytes).
        // It's initialized to the machine's initial state in the constructor.
        // NOTE: We mark 'curState' as 'public' because its getter is the only
        // 'sanctioned' means at present of obtaining output from the machine.

    uint256 public curState;

            //|--------------------------------------------------------------
            //| The following state variables are used for implementing the
            //| simple "single-shot" input model w. participant authentication.

        // All of the input values received so far, combined associatively.
    uint256 public combinedInputs = 0;      // Zero at the start of each step.
            // This is only public for diagnostic purposes.

        // This mapping, which is initialized in the constructor based on
        // provided arguments, maps participant addresses to their bidder
        // IDs (integers 1, ..., B).  This is used for input authorization,
        // to ensure that bidder inputs can't be sabotaged by unauthorized
        // parties.

    mapping (address => uint8) allowed;


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
    //|     The constructor takes two parallel arrays as arguments:        |
    //|     An array of Ethereum account addresses, and an array of        |
    //|     participant IDs. Each given address will be authorized         |
    //|     to provide inputs for its corresponding participant ID,        |
    //|     and no other.  Participant ID #0 is special: It denotes        |
    //|     the Unlocker role.  Other IDs correspond to bid-               |
    //|     der numbers in the multi-party auction.                        |
    //|                                                                    |
    //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

    constructor(address[] memory _a, uint8[] memory _b) public {
            // Arg _a is array of ethereum addresses of authorized participants.
            // Arg _b is array of corresponding bidder IDs (or other participant IDs),

            // Remember the map from participant addresses to bidder IDs.

        for (uint16 i = 0; i < _a.length; i++) {
            allowed[_a[i]] = _b[i];
                // Records that address _a[i] is allowed to provide input for
                // participant _b[i] only.
        }

            // This just initializes the inputs[] array, which records the
            // coded inputs that have been provided by bidders so far for
            // the current time step. None have been provided yet.

        for (uint8 i = 0; i < inputs.length; i++) {
            inputs[i] = 0;
        }

            //|--------------------------------------------------------------
            //| The actual "logic" of the garbled state machine is here.
            //| After specifying the garbled code for the initial state, for
            //| each time step, for each arc index, we have an encrypted arc
            //| representation comprising two 256-bit words.  The order of
            //| the arcs at each time step is random, and the encrypted data
            //| looks fully random to anyone not holding the input keys.
            //| Thus, this machine's function is fully obfuscated, to the
            //| level of only knowing its size parameters (number of time
            //| steps, input variables, and arcs).

        sInit = 0x2f7214f79f2ceb951b7b6977b40cd11ba42dc00111ddd1bf62026ff82ac99e09;

        arcs[0][0] = EncryptedArc(
            0x53f43fe4097043282de5967f662a55eff608710064439530fe4ed221bd8127de,
            0x5af8cd7be092bab8d4fe5f2b31c1f2add08c4b233ab5d5cac6ec9e42318afd14);
        arcs[0][1] = EncryptedArc(
            0xdb265917a34194adfc382d41544d39e8f9e36a03205b46ffdc26dcf16a6ee14d,
            0x78ca65b2714527165b9f04d52c5ad513f8e91d53e2e05702f1ffbae128f13145);
        arcs[0][2] = EncryptedArc(
            0x1199e8ba1d4f0001e45a5d880f5c26c3bcd51d568592579a3a2a12e333040f79,
            0xeb9f2f7c50486d56a2d233bda62b7f62687b8c396fab446ba25ae9f55e444c17);
        arcs[0][3] = EncryptedArc(
            0x8a0db52fa70f524daf6ed1edf33cc32e85e0d02a9fa3e45903a0598542325a70,
            0x3999292c07f6061993c47de097c56dcfedbb16fa6f1f3967eac0479e85253729);
        arcs[0][4] = EncryptedArc(
            0x21dcbd0af27e6062e8b78c8982bb038ef62aa585d0db859a754dffae7b512db3,
            0x496b2066928d8d5075325fa646f4d092a0bc011fb988ba579150cb202398019e);
        arcs[0][5] = EncryptedArc(
            0xf0a562d8ed72cedbccb584fde1c8fb268c2e18e86e4fba493f792f1f1d4afb9e,
            0xbfa92600048c30f20409277a25332444dc38927d296abd2758761dd428b0b7a3);
        arcs[0][6] = EncryptedArc(
            0xde5c4a4076378e69df193b74e979639705aee013eb998e356a81cf5a11c405f5,
            0xe930c844f461671b666541d6b9c50cb840fb8bc37e1b036710a2ec3e383c86c2);
        arcs[0][7] = EncryptedArc(
            0xf986d28d783bc123dd0c14fed02c1cd52944070828282a764d14679acad0347c,
            0xc2e6cca7596887d7555f1eea011112b0d8fc78a3019c42da71cb769c1bf799da);
        arcs[0][8] = EncryptedArc(
            0x9f36e078fd880f11093156cf9f168621f5a9c3dd2d4eedf26ecb7297fa2d157d,
            0xfc31cd1827e57ace2820287fdcce1f6544c4a2921cf91c1f9e399b5aa9cd5636);
        arcs[0][9] = EncryptedArc(
            0xcea8e23d572a4f431246dd8fb6aad3a3ca2cb2ae740a5763b6aa5f0cd1eaa5c8,
            0x2c957e9d01d9ea43b4114c6d570994f04b5e4876983d9d3909f805b454db9412);
        arcs[0][10] = EncryptedArc(
            0x15b9fabed064676fad26b2464bb955d044cc77fa80f4e9f12cb43f05d8a62b1c,
            0x4b9260d6691ebb6ddb54fc51bf6d7d9c286da4295d5ccdf6ccfd249130c0a9f5);
        arcs[0][11] = EncryptedArc(
            0xf91dfe341f070706c585112ec77e8c4909a0dda8e0df94eeeb3dd77af52615b9,
            0xee10ab59b9e7e56ae3d5d26eaf3cbbd4511a4566adff9bb6e38392dbc301052c);

        arcs[1][0] = EncryptedArc(
            0x46d9f40d64e0472ced5f93078a04514340124a35c31252b0d747d6aea4e400d2,
            0x1f5077483f5090a354d8f25609b69256975c0c1d3c54fe84e7d0d95c5560d835);
        arcs[1][1] = EncryptedArc(
            0xf1665b6efa307897242ded10e2c1c648aaeb59a62b2a962244ea6dc49ac1b37d,
            0x0baa8e240c1b026da25a89d6ecfbdea2f4dcfa2ab96a11d1295b5d2a4c992736);
        arcs[1][2] = EncryptedArc(
            0x0cb8031dd9a7e9deb2d71d123e6ac4462fef089f74f30f8fbeb5e62ee599f028,
            0x5219ba9991ee7a7710940691848de514c555b68cd59e1c3f781dc77cf069738f);
        arcs[1][3] = EncryptedArc(
            0xfbdeeb3fa9c3c435685d4f4f3c3880f21a68102877bb338dab943cf66492188d,
            0x10530d74ae7e048684b5b070f8af53e717915f5f5ac43fc61758c56246b55309);
        arcs[1][4] = EncryptedArc(
            0x1318d7a0685cd4b3094cf104ade090df16e61cf8f04fcef7e4f4482682d1b63e,
            0x854463332f4ac3111ff9602488ac5c578d1dc047f3ecd0618ce6b5520b3a4ece);
        arcs[1][5] = EncryptedArc(
            0xb26843c73b6204a24a80eb6c69a98cec9248136cfe7b8d3d3a330db9c9965c97,
            0xfb828cf39df84ef6c51c64292787542527b759713bbee8ce7a671125df5314a8);
        arcs[1][6] = EncryptedArc(
            0x87313a3b06f19a0bf897db1468f4e8b5f1ab1ddc44e42c91155676934d738bab,
            0x833fcf9dd40a087d12e9f37064cde27267326cf97ba8e4aa10603e6f595e648d);
        arcs[1][7] = EncryptedArc(
            0x2e61770f301e693ba7c4f5e2b1507c96437febaca481a98ec5de644ef883ca7a,
            0x9aaeec1f71dd477a89dadac7e70423b8954c6149186c2089270a384ec7a9b83e);
        arcs[1][8] = EncryptedArc(
            0x56c2cfb926a76205bd17109728d93630d79c829b4dcfce0bf483f5a5d8c82711,
            0x26c972b34ab8263d4ec251ea0bbf348c57fc75d74ce87aaca9fc63a54f870b90);
        arcs[1][9] = EncryptedArc(
            0xd418c1f84267a5c6a2fd16718857df0a941758c951f381ce0222b19edd65c16e,
            0x8c70a19411e9e6e6525e1006edf9f23dc9ca2c92eb5a1e94b17a076efcc1c0d5);
        arcs[1][10] = EncryptedArc(
            0x9d8cc3afefab17d3402e20c93313b4b81cdb59f20726daec9518437d8b683db8,
            0x05f3044483f87e06715f89cfbd7b3641e90883f8a1127ee5331136c9783b3ef1);
        arcs[1][11] = EncryptedArc(
            0xbc16b24dfce94b93b46141684af8342eda137c05516012eadf07980333f87b12,
            0xf2b8e4370971ac291feaa9677fe3b8ea0577e728c4aafd5a0ed9163c8fe28776);

        arcs[2][0] = EncryptedArc(
            0x98534cd89a209310108f63ab01234a8733bbf5d987624838bc7ae14e034cfa95,
            0x8401a9c6bd6433b3f05873e6f8a06b2c60db65225a1b191189af30b78e4efcb8);
        arcs[2][1] = EncryptedArc(
            0x3db9c9cb337267832dd110e53322bc604afa4b9f610509bf9e6020a6b2c41c5d,
            0xfe52573af4a6af8950d966ae7e114035f75202c7308aff456b87a72f7e9bf839);
        arcs[2][2] = EncryptedArc(
            0xf4afc7b403dc51ef02fc54c6936064182c0f8a2c483b70e292326395a268887b,
            0x1832554bc87cb85a09de66f206eef286776aa0eafd6bab1d096d5c8f9d4ba03f);
        arcs[2][3] = EncryptedArc(
            0x26839f15237d964683f1735cdcf7c3af408412ee56ea1a3e6ea2b24ee0fec199,
            0x1f5ec09be7cea1b6f3acda0440b62c47142be497358222dbbb462d2bc38f253c);
        arcs[2][4] = EncryptedArc(
            0x1b99d8e805e9d6901db0da09ed4682abffbe01cc1dbf3dea7e0e1b21a982de5f,
            0x9dacc211f5832c1cac1723660e94ce0eb9e58873bdbde8bfa7f513c863cc0ddd);
        arcs[2][5] = EncryptedArc(
            0x3ebc913259dd5a427654ef4805ca330864c9190cdb2e4053e1dee322d6d95f2f,
            0xfb30e6d5d1cf5b5e3ceaca443b14ff1a5a77383e77670f173e0eaffe5ef7faf1);
        arcs[2][6] = EncryptedArc(
            0xe4608d0b142b3157d23d92f7c2d235cb963f92e6c5c310dd8f0bc23df8c8dbdd,
            0x845f33825cda17b321a30af796a479360c6c23922a2062bce0375ac7d4495aa3);
        arcs[2][7] = EncryptedArc(
            0xe5003cca58c7cabddf5f58e2da07690618ac6b15f3f597a3ccad54ae72ce85aa,
            0x18edadf3bcd05b0fe5c74f0904651dd20b84e052ffbdaa116c6fb6a1054d2e55);
        arcs[2][8] = EncryptedArc(
            0xc24ea6825492056829ff2af166e645d2d4c81eede10b109ded348be73c0e21fa,
            0x47e9f946e97d16bbf59ff273494245108f02151a0988cbd5c2f03ad90ec4214b);
        arcs[2][9] = EncryptedArc(
            0xe52945bb4c3fd6961e7527f53df4360633acb46258f17802aa354f0315937d70,
            0x3ae30b91ac93d3d233d2b5bc19b371a35c67737bad839f8c5cf61b59f750e46f);
        arcs[2][10] = EncryptedArc(
            0xe4e3d75c90829ba5ac9b268930aba22ec4d39abdbadfee8adce5e1900fb13e3a,
            0xe8ab4f6b99ff906e1e7c44818c8a18e07c6da146e418de2d43eea6f3505d044a);
        arcs[2][11] = EncryptedArc(
            0x14b8175b8c531e1c6ef3e947c2560bc509dd902d05a5aacaa13e5ecd469e6969,
            0x5cdf83d4fe039ce9588e3a12ff8a38a81aeeef0f042bda4aa4024b7b854031b1);

        arcs[3][0] = EncryptedArc(
            0x2b67e3ea3eca804e1f92231e255a07ff50642eda0927b50634c1ecd8267f907e,
            0x0ce283902de2dddd25ec7833071c21b0b2482285e2d3782506aae2b403934ad7);
        arcs[3][1] = EncryptedArc(
            0x6c9b28fcdc0171ff66e93b473a030974b7b77c8bc2bce21c24398cdd3f48fec4,
            0x7ff03eeafc1d2cd74ade9da825275ff557ce1e263ccf9b4d9338a19a30e1dc4a);
        arcs[3][2] = EncryptedArc(
            0x6242374f95860f0d950f65b9914aaf6d950d4865936401c86fb09c09157724e4,
            0xb81e7f90b52c290898aee8a1b4699efd54bc9eecdcff162cdc672134455f78d2);
        arcs[3][3] = EncryptedArc(
            0x14b4fb9537d3b4bd46865f7216b981bfdb51eec5475ada043124d0bbcf5326d7,
            0x68f62aee3fa5e7f102e43cd2fc45fd7b96533e004a0aa1f5f6eb1f07d297f754);
        arcs[3][4] = EncryptedArc(
            0xcec3b5aae8465a5e6ddc378fc9bafa5b1c7289ed1fd06ac91016bc1bd8ad62e8,
            0xddf8960debf5b69e0527a504789a3b924fdbae2998deffca06126d11bd385596);
        arcs[3][5] = EncryptedArc(
            0x88243d77f68fa11a39fde3366e275bbdd2d8412c9f409eea1cca5f7b24f17562,
            0x7dea60c6a7164b408253da00d934d7f0bb65f8cfb63e4446949788e903df9312);
        arcs[3][6] = EncryptedArc(
            0x1eb70e43ee949396a8bfcbbdbb7542b101eeaf5d33bf45fcf000a45f08cfc139,
            0x283f589ec78425e868edad2daf85e75ff67fbe9a8c6080b9abc2474b2b52e244);
        arcs[3][7] = EncryptedArc(
            0xa97b91d7b5fdba80ea652636fcd6923a36ccbb7c3fd5b82ff29ed5be6e9fbcfd,
            0x9822e35b74a4e350c35d31342189e692a5f7312eb6a8abb59c9ebdc9241c068c);
        arcs[3][8] = EncryptedArc(
            0x49bb44e988c40a90e8240dd441a30a9bbf443f1a525e5c80297124dae8236fe6,
            0x733d5820436b5da6403743fbe3075808c990d76f164cd3a9c904a4101646794a);
        arcs[3][9] = EncryptedArc(
            0x77698dbcd57fe3a90aedb953d01573b72ecc3441da658eed0577661822a905c7,
            0x4908cb0c0b476540ad7fedb5916cefe3b61546fcad3ff90c688d166c7ac13774);
        arcs[3][10] = EncryptedArc(
            0x8f154dfabe96289195a33ebe2466d8feeb83e05d3c2df360555aed3b57794e21,
            0xb04df51c665fcc55366b4e36761f015fd03529cabad7a02ba978a39404c46d64);
        arcs[3][11] = EncryptedArc(
            0xdbb36a2340576e11e8bc95718cce12af04b05f7f58e12477c9e20c833eb1a80f,
            0x51a68778e6c852d2e082b1996a88297578d37d03fe91c804ee45e655946fec18);

        arcs[4][0] = EncryptedArc(
            0x9f4ec7e93555ca5cbf77d4b4c554d16d5d615b31abb14dafea79d2c05a43aff7,
            0x052ba538d6daa59edf6e83075b2c01e150ba8f10116010312241113928498ff6);
        arcs[4][1] = EncryptedArc(
            0xcf605ef85e80f317b82c327bf4125fc95bf276d0b2eb4ac49faf8f58f79ee430,
            0x8a18e64746a2d25bf6aef5b5d0a1e18664631124e0f0e331575962ddf6baa357);
        arcs[4][2] = EncryptedArc(
            0x8b7e47f99b56b0139311d32e79543666f3fd44373b7333cfdd383e890571bde5,
            0x44bfd8b6bfb32ec14e9e8468d3c84a8055a71213a8c0b24dc853fcfb06198bed);
        arcs[4][3] = EncryptedArc(
            0xecd9bca429b209cdd5e89ab76fbd8697e0eefa70e937e6f8e93edbfa5fe771b7,
            0x71df5c435403611566395d1f3dcdce0a4ad649ff47e229e16b0355a2bbbe87a8);
        arcs[4][4] = EncryptedArc(
            0x4c9908e4ff57de125b0ff4b7c51037b1a0d2a1a66fe228d89277e5c0de8c5d76,
            0x7619c6d2a295ec713f1eaa1a5d21855b6224be73657a0d558cce2a2603ddbddd);
        arcs[4][5] = EncryptedArc(
            0x8e0ebaa66eadd164e3123409e82d81692e779b42fafb9f359e26004467f6bf64,
            0xc45647a71f50a91c44b4befa78c977f294df35c81b6db437b83ea2aa8a85a983);
        arcs[4][6] = EncryptedArc(
            0x505ad59c12e7fc95353887154fa86ec028cb543685721a30a1687a4b39442a23,
            0xb52b59e5ed933dbd045d858ef273d998f33e88378d48891f7a6925fa67b47dc8);
        arcs[4][7] = EncryptedArc(
            0x20dd470b078ad6b2a2ba65fda04a97dc7c0f850178bfdbe50c9891fa17da07ee,
            0x29648246df315217303d5966c6dd3b9960e74bcf62f53c4deda3d5cd8e32bfda);
        arcs[4][8] = EncryptedArc(
            0x262f0fa2a4101db5ec49caea1c1136a00ad802c6fc1df0de79b8ed9efbd2ff8f,
            0x7fdcdadcc466d3dbc0abd75a375d5f445fcc4eb0b63967713abfad5a86e9f2d9);
        arcs[4][9] = EncryptedArc(
            0x573a879d154e5c7dce06f643d4e38fce6b5836e73e2d80aa744e9b36249d973d,
            0xb12df817b40c9d81b78c6529ccf3bfddcecb90cbce3a21bc4adac2f747bc557d);
        arcs[4][10] = EncryptedArc(
            0xe0add441aa5fcef8d7c18673ea5dea83a812575045cf07605d2af3333143a21a,
            0x485af3b4f09cf546ac5a5b09f6b14f7fed0ca81d22e2b94749ab282aaff3eff9);
        arcs[4][11] = EncryptedArc(
            0xf6f5f6980758a697d198adb3d4defd32acd0179b29659eb253950636ceab9584,
            0x150e5c4ded6c88d8b8295ed47a76b61fd0f648ad4a763bbcc49e8a59f8d6f733);

        arcs[5][0] = EncryptedArc(
            0x3793f34fcbbb8b0901b7d9259de4b0f81885907773e470a578b7215497c20c56,
            0x72595c4c663d7d08a7d9c4e118c37535648204155f93632e9da8c60cc98cc824);
        arcs[5][1] = EncryptedArc(
            0x45707b740d537618530c8163e03c8abb992d85d316ea55b1a602095b3f1660fd,
            0xd1ad4d3dd20b338ac3ba40ab907d53d8d4ee32eca377cebc38f01ab7d7ad3d91);
        arcs[5][2] = EncryptedArc(
            0x6700c202c9a5a30a584265ea0ecfdab1a0d559f52416615b8a380223e2ec8669,
            0x0c3b35693096effc6f55846041798824c7e36ed5ccc704a73b1e4b9bdbbdbdbb);
        arcs[5][3] = EncryptedArc(
            0x2064a174c620a625d03b66b8976b1e67b961fc3a9ae8ee486d74e2b122339957,
            0xa9cf35cb0cbf85f911665193b1fbede15c01c65ba4d369861fc74269a6170fd4);
        arcs[5][4] = EncryptedArc(
            0xc10384c27494acb08a743738921b283e35d2c4ece661f8f9df40b819779650d9,
            0x778740f66aad7f615b522545eb3bc7db0bbfe8af1c951578e4e2b2aa979142c5);
        arcs[5][5] = EncryptedArc(
            0xbee1f7910cfe9936052af5f7dc0fa7bc3e877983537d53c56e41b5c7cd7eca20,
            0xd9b8cba61b2ce959a067891eef12cd83d46088489a5971f8eebdb810348f2209);
        arcs[5][6] = EncryptedArc(
            0x7833f781f342938e59e34f5a3e36e27a9dc24dd13705b24f27f62f928651b8fe,
            0xbcca6fcbe97a3f0a7685228ae9bfe4766971bc6ca8aa2b43345ca43c85a26d82);
        arcs[5][7] = EncryptedArc(
            0xb94ef90e5d3a6fb4020247c895d59c2e2f05f897c2962aed771e2f52a00c07c7,
            0x0eeffce5d19dd545ff5063c5597d6a7ce1e4cee9807dc8eef1ffdcff0b5b16d8);
        arcs[5][8] = EncryptedArc(
            0xfc5cc26064eb6d63724f59b3849ce3f92df13703bd115261dce04040e7f0559d,
            0x9abb3b7adcfc732a135055ccb34e00567a360def8b7f0dbfd66ddb9628c00447);
        arcs[5][9] = EncryptedArc(
            0x096899c24c9a3dbf35485e305c8d685eda396d000dc158c208fb2ce97e4b2e8f,
            0xfe170adfa4199f00fcc2d7616385937e8e474d1270e6f9221673ec5a33926411);
        arcs[5][10] = EncryptedArc(
            0xd721d3c9b9d508d035bc090657bf503ae87778ab8e730e248a6795a9016b8911,
            0x9ebd22c7c2026df1be47686db60687d838202c96bfa2d03dbd94d39fbc8a442b);
        arcs[5][11] = EncryptedArc(
            0xa20b57e5bde90b522f0363be66d8ae08d0a4ad7d559f8d42fb51a1f07762e97b,
            0xea7fd26ca77788abfcd143da87341ee89c3ae76fb25c05bedaba3983bfa9d544);

        arcs[6][0] = EncryptedArc(
            0xcbf1afcbb249f56ad4d3bf3723b0064067a868b0def06402f6112c8af884f4f2,
            0x3277e401d7d74d188bbb2ee0697747364d2ccf57fbad7476292edbb030175c3e);
        arcs[6][1] = EncryptedArc(
            0x0c15a92d6e42e987cf23fb4d5cf93db590bc22b0de503b00ac3c25ce3340d6ef,
            0x72662eb99717b1f62c525ffc6652a89e57488db19f3451b50fab309ab24b8b6b);
        arcs[6][2] = EncryptedArc(
            0x80668686f6ffcfdca5d37c5949bcff4b8ab44b59082feac356676d77e80a0b21,
            0x69a814c192ea748eb1ad7a132923ed86e35ae52a48b94f04b3c825a3e6710d9e);
        arcs[6][3] = EncryptedArc(
            0xb8735b0ae9080c3d1567ab50d17a592094fa18da70474af772b6269c0dbdf3f1,
            0xde1a59adac2f64ea85915d06fe53a531c38556ce10c4f3845f461f4ad3484938);
        arcs[6][4] = EncryptedArc(
            0xdbcded3fc657c379e40c98462d763a41b84858619afe78ed9e33d3de2158ec3e,
            0x886a7311b65385aca5827f380d0a5f6ee25724d571447b38c9fd6318a422f5af);
        arcs[6][5] = EncryptedArc(
            0xeed995228bbc94cff6ca19ea4280e0abf02c8224e10eea72107b6a60bac15e78,
            0x6f680de38f3ad7171f21b9e673ba8c92b0f36bb7e8ed8519719bcba17415113d);
        arcs[6][6] = EncryptedArc(
            0x969abdc1881b6027720fa847e87eb3a5cbfdc4855bb41b967339ab32e7a7ea35,
            0x7adb07f149dc9e32f4e857d2763cd7a694b30ea2a7356d77e8cb825d97a45b49);
        arcs[6][7] = EncryptedArc(
            0x26c1af6998a7a4e6e934386655de4b6e815d04655728a62acbaaee5d7941e827,
            0xea2d0763e9d6fb87523c5ad9e6589df8c6cbd45aaa40fec96cc5a644bc1395cf);
        arcs[6][8] = EncryptedArc(
            0xd944dc0ea4e43f5651b81464bb1e9d1cfc0157c406ed97b3ccb8b65ad1d3c221,
            0x0544975f38b823845d755843f049bfec7a4627afe4945c4ce18993bf5a15c741);
        arcs[6][9] = EncryptedArc(
            0x46a461a65dc2b1bbea902b0052ac52317f89ee4015db3f5ce36719b824c2988c,
            0xcebc34a4e83e27f34f5305fa7b362a8ed51ecca422ae687970bf385d008d96dd);
        arcs[6][10] = EncryptedArc(
            0xa8aedf770277246d242129ac92f494abeb7ed398ee3af5d8093d04900808efdb,
            0x039732b2fb0f954ef6e71bd433a106621809eb90ff38ea67e4004185bea20155);
        arcs[6][11] = EncryptedArc(
            0x2769c3e9c4f64ab5942c5093e13becf6ed75a7d6d4736fffc2f7a324b8a206a2,
            0x2e3d181c18a75073d3b3f14a04a40d661320457af9e94516614214b26d5ea619);

        arcs[7][0] = EncryptedArc(
            0xa1dd5f0cf3b68c0fa032acb27515b433f85997c7b724ebae87a30f087197961d,
            0x11cadf3a541f60218402caa45c95a0142a082c4e58031da1ef8009260e144ac3);
        arcs[7][1] = EncryptedArc(
            0x1a51c55cef5e8ba252f2444b80a15917cde5d1ebb5220ec38e4a5da120f82fd5,
            0x581e3f84754b35804ed1645bd9438ea3daff4494fd2ee5b9453dc9d947d874d8);
        arcs[7][2] = EncryptedArc(
            0xcc2c22d100d0cce99c624efac7b59cde60234e1009325c4a94b91a95a43608cb,
            0x186974c85170bd35ab97ed66ca65639b945e05ac7a893cee9904fd81d5fcfc7b);
        arcs[7][3] = EncryptedArc(
            0xeda8c0a2b4b406f3d9e6331d1912ba85dac5cfbe69ea31bbb93232f156357543,
            0x91f2bed0e2293a3ac6815c6b6e629a74c625a40fbf61fee6924f3dae652426fa);
        arcs[7][4] = EncryptedArc(
            0xf374b794258901ea5c3fee033ee15d39003cbd8753e55287b34564039fa8c23b,
            0x6b10d3085a04b0bcee0e0545484cdf649beee376054d52313e43cd3e152a239f);
        arcs[7][5] = EncryptedArc(
            0x7bd1593b3d4ad5a05ce98d950b168c52b430492c072e23f28ae88f5979bb9d2a,
            0xa04e81d0a32e77d42152f29a5aa0bb1fe464f5b0a516dc8dac55d6695559b7ea);
        arcs[7][6] = EncryptedArc(
            0x5ea0d2e72b185b017ef5f645c97b83f2f18467ba5d705002c17bf3400b753d33,
            0x6cc8db89ed52e0c36eb2ba846558dd91c4c1c44a7d98c99f71d7a979e8688cd4);
        arcs[7][7] = EncryptedArc(
            0x85c97db65607634b4e8759a0b681b72e0f38660704d416d7556af6254de09623,
            0x94bbbef87c4d113fd09f34ab767d2f396184ab3751b116c00eea9ddd390d6969);
        arcs[7][8] = EncryptedArc(
            0x59f425935fe229ee6eed10683fa9e65508e9c99052f1a9d1d5d669999c383559,
            0xa0218276700fe0192be34dac4a63da73327be6cfd9f23b99ccea9601a3b3180f);
        arcs[7][9] = EncryptedArc(
            0xba7d2beb870dc5646640deb407725629c4dae3bd1552ce3063ef3624525a67e2,
            0x874444a84a47c6733060f6d7cae895f96aa2091c5bceac475b32db5585ae5d40);
        arcs[7][10] = EncryptedArc(
            0xd1bf652b04f71c562d5c1ac9c358e1b123926d5902665a38c627ce944a51401e,
            0xdffaefebeb805ad4da5e311ca541e67bbabcff00fe9cc0150754d227f9d92742);
        arcs[7][11] = EncryptedArc(
            0xab18fa718b214a056420dcdf6a1c3e3d54f9dbc6077de2f12ceb10ed564bf7e1,
            0x0ba5bfae0521bd9a4deb04a16771afe551da8ff3fb687d8216960ff5de9d06fd);

        arcs[8][0] = EncryptedArc(
            0x070ece7d221095d49f5dc643adac732e34af64ca33d74d84d57e4834a1a9e4a9,
            0x7f615cb99f8a52040fc3f91637fc73c660fe0a48d0d5733087a925e5e485f04a);
        arcs[8][1] = EncryptedArc(
            0x974becfe3f02679118c4eb8b4230bbc129d46df34818ff3410f05b6caa3fb1f6,
            0xe574568397f1b880a95e9f5e4605b85dd12cba6e95bdb0d22fd5397784068329);
        arcs[8][2] = EncryptedArc(
            0xd1db1ad7e5085504d2bfbaaa44e449acae26e7aa0566a7cf6bc4609eb62ca03f,
            0xba659a4c8f5007805c69c38b1702e3c5776c02fd472d5264ec0a56eff5e1320a);
        arcs[8][3] = EncryptedArc(
            0x15b547f62237b1707bbcb531f69894fab325bb01f4be5ab42ad54c36d4c15c5a,
            0x6c3ea30a03c2dcaeafc09908c513edd63f8b5245df4b960756bc8cd0b9494d46);
        arcs[8][4] = EncryptedArc(
            0x86de8a67671b6fdb317d14d115bb269287b916def42e1ae55525d767999f5562,
            0x41925669ccfd6600dc0007aadaf021de49c888dbb92aa842b9bad2125879153f);
        arcs[8][5] = EncryptedArc(
            0xa5a28cf847a80dcb986995acc6d085495263b308464c0aa20f1e26b69f37a0b6,
            0xda5bdac07c47ea6537e21ba5efd9a4ef868c06e9ce788c61721cff7f33af324a);
        arcs[8][6] = EncryptedArc(
            0xd9da84ce178bcfeb98df658c608123b948f546d48e46e3841aa6f48980271db7,
            0xbaf23c38817d299c284abebb24352adea36def21c94735dc4c4eb93d269038cc);
        arcs[8][7] = EncryptedArc(
            0x8c60e1c0faf4160bb5a025525b9d665aa67bf345711c1cf71d5d50a6fa6aeef8,
            0x269eedd705079ea95a394cb102a44d98bbedb3b674782d8d9f1eca5144207c8a);
        arcs[8][8] = EncryptedArc(
            0x612e21820759559bccbfdcfbbfb916a954ac08259bfc1e667467e0f63815c631,
            0xb97bc50ac80b5af7a6e9e59778846ed40ac34bcc3091ac2c060d8061c6e683b2);
        arcs[8][9] = EncryptedArc(
            0x5ad66c68db50297cb9e2e8153086f6dd46e1d0f56d38f83c7dea3e8a8b3788f9,
            0x03c77820fa2ecdd811ee3b0a239448c72577074db214d34855a5b7196888d6ae);
        arcs[8][10] = EncryptedArc(
            0x28cbbcfadbafb63aeb8718181f6eab3a1e04c131c7d2bb2f20163545b4482fa9,
            0x353879851cd44871463f2e53b7a2a8b91ae59654493254237138e202f5940ec7);
        arcs[8][11] = EncryptedArc(
            0xc97cdd739224b818c5da3a7863398e2e53ce0059b990b5bae5f58311b7276d1a,
            0xcf3b08dc3d8d174eecbaf3037e2499aa9eb9522ba40dd0db6c7ba3feb2b1a8ac);

        arcs[9][0] = EncryptedArc(
            0x5c74f01a1bf343b2da681afd0d71a04ad3d561ba0db9ad1ee03474900cc0e41a,
            0x0013c449d5789d5475e52ba7ba1d10b814f6d7f7add52d5b1b34c043e20bb66e);
        arcs[9][1] = EncryptedArc(
            0xcbd32a157ee5ee510ac627e1d65da82485638ab6204561f7317a5adcb1bd7d45,
            0x898558fcf264200753c0ac164d1a15c7c77b1527b07f2eb092d3a23e079cfdd4);
        arcs[9][2] = EncryptedArc(
            0x2e7a41f11bf2ea9a54114ee6611ef66eab6e76e730ed6762cce7b1f603050d5c,
            0x4d99258164bdae44ab8f832aabedb036fc87a3bc60e8be7caaad86a2dc86ff89);
        arcs[9][3] = EncryptedArc(
            0x68dc778fb0e008f20c2f40d12a02683a15646d6ea2d81a99e97be4be277de5b4,
            0x02c1aa4190522bb7d09cf73ed98374ae3674070dd00a51ebcb4d4b3b2ab45dd5);
        arcs[9][4] = EncryptedArc(
            0x97c72fa39ea4ea54bde19b10391dae9133c10b65291365856ab41e763a0d6bf5,
            0x0ea6c3819c657f3c96fb7960b3c93ef7289a62b8591d4238d21aaa1ff5610956);
        arcs[9][5] = EncryptedArc(
            0x3c73ce3132a00806ebbf12d4f3f1072e75337ed5b0ecf1f3b31ffa1a07a9293a,
            0x95479cce3bb87d419ba0d1b57f092e2f84b448e13850d19f0c418979ecce3bdd);
        arcs[9][6] = EncryptedArc(
            0xfef77092d92dd439051482903a5d48d573021d7c7bf4432b1e347d69c3e37077,
            0x41e374733b5e7f1366f2e37eb904ad76c8a20a28dbbeca1697326e3cda62eaa8);
        arcs[9][7] = EncryptedArc(
            0x1ad2d86188df69f68a5b55adda7e87afd5e7eda0be71700554f8fbdebada56c9,
            0x47e50aab7aa0b69164a2ba86af346df53945c14e7094fbf6515178f70008063f);
        arcs[9][8] = EncryptedArc(
            0x5546989a8d73bc6db1d462d98a11235045e7efaa1af71831878690ad5b67ea3a,
            0xc329ed37b9459063bdcb82c49ee6e258f2307f30526e48ffbd6f37437c2dd1d6);
        arcs[9][9] = EncryptedArc(
            0x432d69818469db6f005d32deb588acf02aef01761224c8f3d40efa1e2730e9fe,
            0x18cf64ae72e1d18aa84c6cbce8d876ff8e2f1d9e444721d64905bf15e1d7916c);
        arcs[9][10] = EncryptedArc(
            0x726538f46a50150cedb40b89190653392aabb3fbfc22dc9a3af0f0572106e5b9,
            0xd2c2709a3d406f4a01de3ad6774fb85576a541c328d18a9cd91ed028d1f016a2);
        arcs[9][11] = EncryptedArc(
            0xddeb9260df8254ebd8bbcd9a44b1fd49d9fac9c8b2222f4da7ed8dc7dd2e1ce5,
            0x5278c2d9c5adefc879e1ac40f82826ab74259161d163e828c5cc32aed1f34681);

        arcs[10][0] = EncryptedArc(
            0x6de9f826f749aabb7cb1a2a9e78085f0f5dd0fd9e0cd068e724dec02d9a33c1a,
            0xdb8d7af821f3701be70e621295a14b0ea829db22ef4ec2226d3026b989a75425);
        arcs[10][1] = EncryptedArc(
            0xe33293dc0b37f3f7a74199cdde616cdfaceeecbfa01b20ea5bd327c932553daf,
            0x0760c0a086add2008513a01a936dd0915593c90d7a0f57d9cb678d15ae788060);
        arcs[10][2] = EncryptedArc(
            0xa6d749863453320531e70ea10af19faf14078151efbe47d95681f347254af269,
            0x891e86c5d9b4315dbe315ce9f9952a865af1b7c5e0afb7c695720f1fa0a2e462);
        arcs[10][3] = EncryptedArc(
            0x8f4dd6e78104fe6b546f9343f7eea355873be9e950740872f5ab8278a0785912,
            0x92bda6c443f71d3c296f3f46e3c14c2452c571856dc79f9fa5ca06d76cf26e4f);
        arcs[10][4] = EncryptedArc(
            0xc7a87316a275977f2acd896cadc1db8f67152f572362cb3586f5e39e41abeac9,
            0x0fe9172c8902488720667605907342b3ff357e47ded0e1f8325177fdae74ec7a);
        arcs[10][5] = EncryptedArc(
            0x5f768fbcd20f4a6309110fd4fcb71a252983ceb8e8532c9022ec7b4e4aab010f,
            0x8ea23352fbadae6e364a1ab6cb8ced7bf9f856a6ca57d1b6fd8f7324798e1121);
        arcs[10][6] = EncryptedArc(
            0x493975a54b68b5477d6235abd98bc741f7f3a71b28fdbf80ef9b904ab0531344,
            0xf47a0dcfc775e49a41e78304dd9c09d6c2f7d6f52621930312ac5b35f1f9a45e);
        arcs[10][7] = EncryptedArc(
            0xcb8ab0326e063e0daa971c3f7711875b7a9277ca8b8adc2a299385cca934da1e,
            0x26db1c079d3f272c7ad4a52c3b7b38672b3389963691bcc7933b14b18fc38691);
        arcs[10][8] = EncryptedArc(
            0xc682ae0c2c99c6e6c4b1743ef05382774e5838250c40060ac601ec5e514896c4,
            0xc5436b686d3529353dd3fd9389670d497f14f52997473d101c8a580e0983953a);
        arcs[10][9] = EncryptedArc(
            0xfc37534b4d495a56ab8b22280a894e22b59c2ca685e8ad6d967159939f8b43c4,
            0x075cdf63c7cf75164a4515558b87a089b047bfa0f65f9e1598a08829868d54ec);
        arcs[10][10] = EncryptedArc(
            0xc280301777bf4fa2dd9164f3d6f93cefa8c96f6e7c55a6163b30019f78bd3873,
            0x577f3eb6e420f6a3da2c76472b5f1754eaf1c1777985231575f2d5e93ccb9760);
        arcs[10][11] = EncryptedArc(
            0xa729cc960d00900ce6573eda4667856a2e51409769f13d066a3db50680050688,
            0x2fcb68a1623a5db32327eaa6965980e4ae8c5cfdca2725bb51c3c3eb04fa2f46);

        arcs[11][0] = EncryptedArc(
            0xaffa6c6e6c79bc6cc4cd4fa79de8201bcd814531c04acbcbd7c5feb123de16ac,
            0xe494bca70e874bd7b5d74e2eb2901f057b9b2226a22b10de318e413021bc8bd8);
        arcs[11][1] = EncryptedArc(
            0x338886285c42ddc504c947b940f9ad2e6fa7371d9112f0ac2edfcbdc7684dabf,
            0x84126e58fa4be0fa3c3f931d1836ef050410e69a97aaae8a00a6c49f20aa4b49);
        arcs[11][2] = EncryptedArc(
            0x85a9d70f011d65b3f2bd3e9b1e7abe55bf80d8ce58e4356afef732cf4e12b04b,
            0x341ed16c705ded441f0d80b4a609615e36b6c33cac46fbb8c27223d879920ef2);
        arcs[11][3] = EncryptedArc(
            0xf96b9228e64e0392f09d6d0cfe6e13f4051fb570db0ff9d5a575e2d38672c984,
            0x95a27c0bd425247ac121c1a4e15210bebbd550a9aef4a263fef5ec2b5614d60e);
        arcs[11][4] = EncryptedArc(
            0x1c43530f075fe65fe89fbc7587f28e83f2d5c8b2b21d2a58589eaf47e3fcbaae,
            0x0a8a5d5746004d36206715047559dbd0528c5e58b04bf1c8ddbc1f6fe18a2888);
        arcs[11][5] = EncryptedArc(
            0x726a129cf1ca124a9eebff412536b1993fd17e6cae5faca58edcb1460a847cf7,
            0xc73c3fe3df6e73a5a52edcbb98dbe0b56735961bf9911a7053375c4bc55ee90c);
        arcs[11][6] = EncryptedArc(
            0x78e283ad289e0c564821753dda63658d475dba069cd0ad0e3a9313eb6dc96cfb,
            0xf9cdba59745a794bf2bb1994aa254c9805948253896088220f9ea84c32397645);
        arcs[11][7] = EncryptedArc(
            0xe92634a27f0fd92c49053fa8400b479b85d9e15a8aa7cf8ae75472bc40bebd2d,
            0x6122b71efefed9147f56c81342280085394f591b3cd7b316009ae8554129f794);
        arcs[11][8] = EncryptedArc(
            0xd4661b60ed64502ca5a0a0e45beec23cb2a9e20fcc4bf6b43c7c585e656da4d0,
            0x29a604f671d054cfcda68a4743151b70175c67e986f2bfdbaba885080d5167e9);
        arcs[11][9] = EncryptedArc(
            0x39bd6db37e5a27fab6e106426e0cd060b7d0b9674fee267b57bc68720c1d1ff8,
            0x3ed81775c88039034238cc41712c5735cf414c0ad07be20afa7f50f71a06c4b3);
        arcs[11][10] = EncryptedArc(
            0x79dd368d67f8c65dc950af1fc517c779b7261251df20c86409853ef2ae0e9c81,
            0x68acd5f96029686d2e6ca9808d55158cf622907d3b39d4c8c260275957c81962);
        arcs[11][11] = EncryptedArc(
            0x35207fd4279bf2f64922cb864db8b82a8c7c9161afcb9da8926b4568d7fe9071,
            0x62a9cddbfb03889982991266f3dd8839bed1a712996f1b1bd7b58e8fc0944253);

        arcs[12][0] = EncryptedArc(
            0x183660e10dd0721fc9fa733d060d2d864309c6615d071ddf8500c14e16a57782,
            0xca05949a385fef721d8dbb6684dd2c81984276657c0740b0d613b169a5538467);
        arcs[12][1] = EncryptedArc(
            0x7af33f5c6fceaae78cbf8b068d8a2460c6786d41c3b4987b7098f7fd027e8f7f,
            0x645425bc3419a683147a9cfe5352708b2876c4afad6f2296e7cf78519ff35e61);
        arcs[12][2] = EncryptedArc(
            0x577effe9ab3b36d116faab011f4fafae4fee165c25201154c854f573b796f2a0,
            0xa5b71d094f713cd251d4382a69696065addd0805db8085707551302d0f11c1c5);
        arcs[12][3] = EncryptedArc(
            0x3711f864e84e4e88565d5a90dd3f7d556637f04650b67c9c72e48c43b9d04034,
            0x2b2f399a00c8364a8a968baf2ad4cb2a14323a3a76e281a811439edb546dd33c);
        arcs[12][4] = EncryptedArc(
            0x9baa190fe5763fe902255a2b45dc493415eac3fc36aee5ac3c2c3fbd8a6353e0,
            0x5797199972b0edd69999ff9386a485f03ca92a5440d906f520c99e183044297c);
        arcs[12][5] = EncryptedArc(
            0xb9fa1af66e57285ef8644c35b2efea7222363b539f424add584a5f21665b8a6f,
            0xf1898ec1747ffc33dbf6f5264a6a773c636b94fc43ec6cc1605059ba3ba7f98f);
        arcs[12][6] = EncryptedArc(
            0xb39278755f4b500798ec6739504df4e1170a91cfb7a0ad7eacb168bc88db69ee,
            0x58af2bc4ceed3b6d4a5304d99d53c552feaf4b726b9326eeb3de6ad5a62aff5a);
        arcs[12][7] = EncryptedArc(
            0xbb3b98afa9245c55a3a478a5745bcab824d58bfc05cf65b3ac62667ca2ff2f3c,
            0xca44b5156c869a94cb68796e7a758b65495ec943dac029b6ddda2f8245ef032b);
        arcs[12][8] = EncryptedArc(
            0x0d263f155dfc23f8896588e0d583c79bfc1fc98e89485b7a39fbd9cd81d4cabb,
            0xf8d0c9c935b709a1648d4e55f92ffadbc3c90acd5f5bb484a57092ca9203edf5);
        arcs[12][9] = EncryptedArc(
            0x8b6b45a21409c7d1d50fde65b7db902d38f47b2a76d282e67791af4bd082637a,
            0x20c17535072b524edf10673d9d83ced28764537b4f0b50601367e33d8d77e6c3);
        arcs[12][10] = EncryptedArc(
            0x537c40978cda50dfb6d78c72af5563f86f41f0054d2e7e6d319563264d88209a,
            0x1b05ec1e19323a6c8fbc4ce481a643a83915df96a36f5c3a26a092d2f4818c29);
        arcs[12][11] = EncryptedArc(
            0x509d969d36c988c344ea5ec3dd37a41de428194c9617ea8230d398734741feae,
            0x25c06df4cf46d3e5ac841ef4f287968b999de81485bfbea38042cd6a9e34c729);

        arcs[13][0] = EncryptedArc(
            0xe090f4abfedf7cbc1e2621000d02a115092beef3f42537c475919ca237b52d2b,
            0x0da598166e0d31d37dc2e997a94b1b48349ec02b03ceb4c2d2dec6f9ae8ad3d7);
        arcs[13][1] = EncryptedArc(
            0x7a64fce3bb46738a1a1cbb84e79b4b9353595eb91b3b6a7c2bbaae0785a7eb86,
            0x4b7bb788541d055d4534efc92cbe38b8628cf33724255444a85aaaab122a29a1);
        arcs[13][2] = EncryptedArc(
            0x1b87bd6456aa2ce4f5873ff7168021ac8c1c73a12073a27670aa43563fbeb735,
            0xbfe4f006003a4b9082ed839aa5e54226b3e2df8fc83b03f705bfb3b673144f4c);
        arcs[13][3] = EncryptedArc(
            0x06d605f4b741e47933eef436f8db312b96ca6ad2fc78fb320ee1e8fec51887b8,
            0xb74f2cedb08d359f64a3ff0481809a7cd862a285a02f0f042da6d7178a3d1007);
        arcs[13][4] = EncryptedArc(
            0x42048442787c277caa97de8fa0625a10e8e743436dcd13aa9ef31c93b1d5d250,
            0x9b58d3ad3573de8f309fcbb096929b96960b75d31991f971c85c459961f18f3c);
        arcs[13][5] = EncryptedArc(
            0x0d40c7daba4dbd4bbf0b119b3bad67521b2a874b20afb0f1bc38d19f20077790,
            0x529cb228764d0dc4106c2c478cfe2c25b948eaf65d27087ea013462a144f78c7);
        arcs[13][6] = EncryptedArc(
            0x61f810e0834f806921ca3752f23046693944f61a4214c7178f9ae2078967b99e,
            0x965e9ce7e43de539920839b34d6f003bbffc0d3187924f40667a1643b10684fe);
        arcs[13][7] = EncryptedArc(
            0xb1e65942e132664dfccd628c8f8761878b435dc1b3f8ba76e68807e2fe0891c1,
            0xb42d98d8b02c92f43fafb4764add9d532170660b54432b3df0db9c5ffd0d4b6c);
        arcs[13][8] = EncryptedArc(
            0x6de9514eb6cad5214d7182896c3af7959803526685ed04d03cb2a1b99324670a,
            0x8cd8a81d7bba9e9e2fbfa94ab26d55ee6754360e768775b8ff95a1a3ca7bb85c);
        arcs[13][9] = EncryptedArc(
            0x01c8534e02b0be8c7470a28f81a6e4c45bb2ebaccbb20d01d4686410ae7fb891,
            0xa5559caa8a9b441ec919d28b5f94b8d4794671584b43d649cb70c6d55624c864);
        arcs[13][10] = EncryptedArc(
            0x5d037e027ac2cd873496168f19901f2682228fb0023230ef0613a3f3827e7c59,
            0x12792c678f07396f22806eaa29fd22ea3b9aa84ea8482bcca5777a1e81957531);
        arcs[13][11] = EncryptedArc(
            0x6841965ec64b1112e5850bfa526fc8902c521dff7fa87a65f281c57e00f75c01,
            0x886457f7edfed0b33df5ddc4b0ffaa9922e11269517f21bbb1d94f7bb33a688c);

        arcs[14][0] = EncryptedArc(
            0x10952a3ca9597945e2e1a0053256b01595692530f9feab0d33f8d720fe127d98,
            0xf903af71ab6dc62edf8f9e56cbd1109c05dfc4ae0bc79038e95c9c47b547b8a6);
        arcs[14][1] = EncryptedArc(
            0xc9da40da7f2333d07dfb1f704537389516f43fa9eb1c1a5d81e9de9985ab38f0,
            0xf88b7b321b926637d4075a37370cc8f6dd3d7c6e892db8eefd5c42033586d759);
        arcs[14][2] = EncryptedArc(
            0xd301f0e6335c50087c77d68f841f17d1213de695e4d0ce15038b87407d9b3681,
            0x5dc99f42c3eaa45a1cbcb17dedb34a8ce5012b43c1eff9b3f594019960c82e95);
        arcs[14][3] = EncryptedArc(
            0xe2df567760ff53f4e4aca8fcd0640d651eb1e0c4ae2ba615cc51c86ff7229e89,
            0xccfb16ec578247191cb903c60240bb58ff8c5a18835d0afa3cf82af12b8ae669);
        arcs[14][4] = EncryptedArc(
            0x622aa497976da713723beb9e55f9b38cc9b806aad49ceb24ea35445ab03865a8,
            0xda6c5df52d62a3a87f9ae334f284bccc13ad27abdee006224ed886b917328cdd);
        arcs[14][5] = EncryptedArc(
            0x756d68ea4831608c51c80f09f3006722315ded84f9da12c69cab05483eaa82cb,
            0x0e5880c53c4391e7edca1890325d489e57fad732ca8e47b88a75641598b09c62);
        arcs[14][6] = EncryptedArc(
            0x9c69c6c0bf9dc7f32fd0afc8424524c16e3aa1a1c7afc59f69d0cd5505751505,
            0xeb97ec7ad1e767ac86a6918aaa30b8e289f2911bed60adfce14cfc0b813a5e16);
        arcs[14][7] = EncryptedArc(
            0x1726e41e30d484a0c9ec5fd0616a38e5df005b4e173ae35f7138506eabf79c90,
            0xe0b88b1ae0f1623615f1b71ef39a991b548c245c9edc657b7ede27be5d3f5f21);
        arcs[14][8] = EncryptedArc(
            0xdfc496d5a415d4c697f5d501d626b9201ce1285830833745c4cec2ba8cfd4a30,
            0xe232365bf9818172be971130cf472b90498c917842e9b3b0556e48bc6384ac3e);
        arcs[14][9] = EncryptedArc(
            0x9ef198e61b42422a9550253162e8566581247f45d8ceec19789d820384a43bdf,
            0x0f18e2d1b971e5aa471d1ada915d4b815ae2029474289cb83472b57c8305b7fc);
        arcs[14][10] = EncryptedArc(
            0x38c9661ff039007e66baa222baf15ada72ff19d6e345fbb75bfa5489cd158cfb,
            0xa593118c580d5b605204ba0cfa796f76710ee3e069c30a7b7b582bd12e14b80f);
        arcs[14][11] = EncryptedArc(
            0xc1718b58407e782076314910f4e240820166f86d0e921476d9230e3d76961d26,
            0x10369fc02a7398f4af556ef56d7c805bd70210ed3ecb2b8c88b38353db4c27c2);

        arcs[15][0] = EncryptedArc(
            0xd834c459531db44072f37ffc16c3171d08eadbf353a60b60323f405b25e97b0a,
            0xbef4ec608b2c74204a97972860fdf03e069ab73bb05395b20cf5ef5ec2227a84);
        arcs[15][1] = EncryptedArc(
            0xce0647f1b9a54a9b56c62b533a4f14a6655aa73ca15cf743fa6f5ea79a45441c,
            0x817c1465f01b70509184d417e0dea05cfa0204088c184d298b171b943c996500);
        arcs[15][2] = EncryptedArc(
            0x03cec54ad1ab624792c8d33d4e8d963c3ccfa1c0f3abc8c3686346cf473a5bd0,
            0x6c18e9e187d3e5cb14af182dba015bbf488fda1988eae3aaef050404f0fe6770);
        arcs[15][3] = EncryptedArc(
            0x8c7992cbc2983cc9536c675f18acc7c2ad7ff625207b95a92e65a73a631367be,
            0x2489a72f564f1f8e4cf7cbe8b05e612c5181bc07d3734c8b957b85871671760f);
        arcs[15][4] = EncryptedArc(
            0xb2ea4abb4298cb582591fba954c8cca1ee30db05a9aabd0baa18e1e8c4a57166,
            0x264c33ca5b3c087624236235fb59526ac8b3e26c82f75a02e470c16f0f2ee4f8);
        arcs[15][5] = EncryptedArc(
            0x14e227d327a56aa7f7a6bb705effc5cbbaf84e9205e15f9f38312dc2c977c33a,
            0x3533947af697ffbc62f281d91ee4cc1fb94ff2760d732a91449916fe026867dd);
        arcs[15][6] = EncryptedArc(
            0xbbd4638f83484da43b13bcc830be99937f61a3b4141a63aa6c9800c9a3b60557,
            0x5f2327da5a7525e47596ab14b483278f6bc3902f2f00721d9957061f518fa1d1);
        arcs[15][7] = EncryptedArc(
            0xb2185c868ad176c536dcd4a2014a036b9025fb60b134d24283e2e35a68456ec7,
            0x057bd78f7dae327baf10137a7b0e399faab21fd9a82b10e5c7d182ade6430d1d);
        arcs[15][8] = EncryptedArc(
            0x3ab15f310495c2967c065041a34debfd20fb5505abd781742ccd641e77296e2d,
            0x1dbdfaa4ffd5632ddf94fa951bd03782a92d2da4716b2d50a45d3217a776156d);
        arcs[15][9] = EncryptedArc(
            0x4dcc98e7746e1d1806be6f335bd6148b7c229873bcf2e6c739de04d2226e5fea,
            0xe58ffe1d5713524d0ff31ee43cf8de0d3723b27302f91ef922c1740010aed334);
        arcs[15][10] = EncryptedArc(
            0x8cbed4086cac9d3737080e5c8cef277567bbff617c95cf3129fe614ec2dbeb8a,
            0xac5753f4159170b4217637336d95ed3ff1d263772caa5297106e7924176d9710);
        arcs[15][11] = EncryptedArc(
            0x86276d06b7d58779cee94e857d3cd37b5a45f0267cf49a3138ab3cee159d5f04,
            0xe5e3d8ebe39ebb9af47985e5d9538bf14a76fd39c29625cd8331567d746a706b);


        curState = sInit;   // Initialize the current machine state to the initial state.

    } // End ExecutableMachine constructor.


        //|================================================================|
        //| Public (and external) functions.        [contract section]     |
        //|                                                                |
        //|     These constitute the visible external interface            |
        //|     to the smart contract.                                     |
        //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|


            //|----------------------------------------------------------------|
            //|                                                                |
            //|     getInput()                          [public function]      |
            //|                                                                |
            //|         This function is provided for use by the               |
            //|         Unlocker, to retrieve the coded inputs provi-          |
            //|         ded by the bidders.                                    |
            //|                                                                |
            //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

    function getInput(uint8 id) public view returns (uint256 result) {
        return inputs[id-1];
    }


            //|----------------------------------------------------------------|
            //|                                                                |
            //|     provideInput()                      [public function]      |
            //|                                                                |
            //|         This public function may be called externally          |
            //|         by input providers to supply a specific coded          |
            //|         input value v to a specific input variable V           |
            //|         for a given time step (which must be the same          |
            //|         as the current time step, to be effective).            |
            //|         It is also used by unlockers to activate               |
            //|         previously supplied inputs.                            |
            //|                                                                |
            //|         Participants are authenticated by checking             |
            //|         the allowed[] mapping, which tells us whether          |
            //|         the sender is authorized to take the given             |
            //|         participant role. (Identified by a numeric             |
            //|         ID.)  NOTE: There is a bug (a security hole)           |
            //|         in this code at present, resulting from the            |
            //|         fact that the Unlocker role is assigned to             |
            //|         participant ID #0, but zero is the default             |
            //|         value for mappings in Solidity, and therefore,         |
            //|         any random Ethereum account would be able to           |
            //|         assume the Unlocker role and jam the machine           |
            //|         by providing invalid inputs.  Obviously, this          |
            //|         bug should be fixed (e.g., by instead using a          |
            //|         nonzero participant ID to designate the un-            |
            //|         locker role) before using this code in a               |
            //|         production system requiring any resilience.            |
            //|                                                                |
            //|         This version of provideInput() performs                |
            //|         single-shot updating: That is, it updates              |
            //|         the machine state after each input.                    |
            //|                                                                |
            //|         This function returns a boolean value indi-            |
            //|         cating whether the state was actually updated          |
            //|         as an immediate result of the input.  (In this         |
            //|         input model, only Unlockers will ever get True.)       |
            //|                                                                |
            //|     Arguments:                                                 |
            //|                                                                |
            //|         uint256 value   -                                      |
            //|                                                                |
            //|             The 256-bit encrypted value (key) of the           |
            //|             provided value v of the provided variable          |
            //|             V for the current time-step.  Or, an acti-         |
            //|             vated input value provided by an Unlocker.         |
            //|                                                                |
            //|         uint8 timestep -                                       |
            //|                                                                |
            //|             An 8-bit unsigned number (0-255) denoting          |
            //|             the index of the time step that the parti-         |
            //|             cipant is intending to provide input for.          |
            //|             It must match the current time step number         |
            //|             returned by .nextStep(). If not, the pro-          |
            //|             vided input is ignored.                            |
            //|                                                                |
            //|         uint8 bidderID -                                       |
            //|                                                                |
            //|             This is the ID number of the protocol par-         |
            //|             ticipant role that this input is logically         |
            //|             coming from. ID#0 is reserved for the Un-          |
            //|             locker role. ID's numbered 1 and up are            |
            //|             bidder IDs in the multi-party auction ap-          |
            //|             plication.                                         |
            //|                                                                |
            //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|

    /** @dev Provide a value for an input variable for this time step.
      * @param value The 256-bit coded representation of the value being provided.
      * @param timestep The index of the time step that input is being provided for.
      * @param bidderID Participant ID for the multi-party auction application.
      */
    function provideInput(uint256 value, uint8 timestep, uint8 bidderID) public returns (bool updated) {

            // First, check that the message sender is allowed to assume the
            // role corresponding to the given bidder ID. NOTE: This check is
            // ineffective in the case of the Unlocker role (ID#0) due to the
            // fact that the default value of mappings in solidity is 0.

        require(allowed[msg.sender] == bidderID,
                "Only permitted bidders can participate.");

            // Verify that the provided time-step index matches the current
            // time-step number. If not, return false (no update occurred).

        if (nextStep != timestep) {
            return false;
        }

        emit Message("Inside provideInput().");

            // The following logic uses Unlocker inputs directly; but stashes
            // other inputs in the inputs[] array for later unlocking.
            // WARNING: UNLOCKERS AREN'T YET PROPERLY AUTHENTICATED.

        if (bidderID == 0) {            // ID#0 denotes an Unlock message. (CHANGE THIS.)

            combinedInputs ^= value;        // Merge it in with the ones already received.

        } else {

            inputs[bidderID-1] = value;     // Store for later Unlocker retrieval.

                // NOTE: We really should return early here. Rest isn't useful.

        }

        emit Message("combinedInputs is:");
        emit Value(combinedInputs);

            // This version of provideInput() supports single-shot updating: That is,
            // it checks to see if there is a matching arc after each input that's
            // been received, and if so it updates the state.

        updated = executeStep();      // Attempt to update the state based on info received.

        emit Message("About to leave provideInput().");

    } // End function ExecutableMachine.provideInput().


        //|===============================================================
        //| Private/internal functions.                 [contract section]
        //|
        //|     These can only be called from within the present
        //|     contract, or (in the case of internal functions)
        //|     from within derived contracts.
        //|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

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

        updated = false;    // Initialize to note we haven't updated state yet.

            // Return early if the machine has no more steps.

        if (nextStep >= maxSteps) {
            return updated;       // No more execution steps are supported.
        }

            // Construct the arc identifier, by combining the (garbled)
            // current state ID with the combined (unlocked, but still garbled)
            // input keys.

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
        for (arcIndex = 0; arcIndex < nArcs; arcIndex++) {
            uint256 valid = endecrypt(validID, arcs[nextStep][arcIndex].encValid);
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

        curState = endecrypt(nextID, arcs[nextStep][arcIndex].encNext);
        nextStep++;

            // Reset input-collection variables, since inputs have been consumed.

        combinedInputs = 0;

        for (uint8 i = 0; i < inputs.length; i++) {
            inputs[i] = 0;
        }

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
//|                    END OF FILE:   ExecutableMachine_MPA.sol                |
//|============================================================================|