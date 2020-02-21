# VRES - Slide Attack on TinyJAMBU

## Overview
The National Institute of Standards and Technology **(NIST)** have been calling for algorithms to be considered for lightweight cryptographic standards. TinyJAMBU and CLX are candidates for the competition, and are designed by the same authors. Both algorithms are similar in design and process, and each uses a non-linear feedback shift register **(NFSR)** to update its state. CLX was eliminated in the first round due to an undesirable sliding property that can be attacked, this attack is based on CLX's slide attack.
## Parameters
The attack is demonstrated in a reduced version of TinyJAMBU (1/7th):
* 18 bit state
* 18 bit key
* 4 bit message blocks
* 2^8 online calls
* 16 bit security goal
* feedback = s0 ⊕ s6 ⊕ (∼ (s8&s11)) ⊕ s13 ⊕ ki mod klen

## Reduced TinyJAMBU NFSR
![alt tag](https://user-images.githubusercontent.com/47853431/75020678-ecc49300-54de-11ea-8e1a-c247f65c0cfe.png)



