# GABLE 

GABLE (Garbled Autonomous Bots Leveraging Ethereum) is a protocol and 
system for performing secure computation on the Ethereum blockchain, 
which was developed at Sandia National Laboratories during the period 
2017-2020. It is described in more detail in the following two 
publications:

* M. P. Frank, C. N. Cordi, K. G. Gabert, C. B. Helinski, R. C. Kao, 
	V. Kolesnikov, A. K. Ladha, and N. D. Pattengale. The GABLE report: 
	Garbled autonomous bots leveraging Ethereum. Technical report 
	SAND2020-5413, Sandia National Laboratories, 2020. 
	[https://www.osti.gov/biblio/1763537](https://www.osti.gov/biblio/1763537)
	
* Cordi, Christopher, Michael P Frank, Kasimir Georg Gabert, Carollan 
	Beret Helinski, Ryan Kao, Vladimir Kolesnikov, Abrahim Ladha, 
	Nicholas Dylan Pattengale, "Auditable, Available and Resilient 
	Private Computation on the Blockchain via MPC," Conference Paper, 
	The 6th International Symposium on Cyber Security, Cryptology and 
	Machine Learning (CSCML 2022), June 2022. Full version available 
	online at Cryptology ePrint Archive, Report 2022/398, 2022. 
	[https://eprint.iacr.org/2022/398](https://eprint.iacr.org/2022/398)

This repository contains Solidity source code for the smart contracts that 
were deployed to the Ethereum mainnet to test two demo applications, as was
mentioned in the conclusion of the conference paper.  The two demos are:

1. **Simplified Supply-Chain Demo.** ([``ExecutableMachine_simple.sol``](ExecutableMachine_simple.sol "ExecutableMachine_simple.sol file"))
	A simplified 4-state version of the state machine shown in the
	appendix of the full version of conference paper (also shown in 
	Fig. 4-2 in the tech. report).
		
	This file compiles to two contracts, an executor contract and a
	separate storage contract for the garbled machine data; they 
	were deployed at the following two Ethereum addresses:
		
	- Executor: ``0xc8a54a72f187ec444ed08968901284bbd6d2ec06``.
	- Storage: ``0x57f1c190982d0a9ecdf7c4703e134d9eaf347de0``.
	
2. **Multi-Party Auction Demo.** ([``ExecutableMachine_MPA.sol``](ExecutableMachine_MPA.sol "ExecutableMachine_MPA.sol file"))
	A 2-player, 16-bit instance of the multi-party auction example
	discussed in Fig. 4 of the conference paper (described in more
	detail in sec. 9.3 of the tech. report).
		
	This file includes a single ``ExecutableMachine`` contract,
	which was deployed to Ethereum address ``0x98ccd7e190ac28a36d4f065a4f14dc5e0b67f5c7``.

See the [``LICENSE.txt``](LICENSE.txt "LICENSE.txt") file for the copyright
notice and open-source license terms that apply to all software in this repo.