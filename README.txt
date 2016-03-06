WifiGB - Wifi GrosBelu

This code performs a bruteforce over combinations of given indications and other clues such as dates, serial numbers, etc,
in order to tyr to match a given wireless network passphrase that is known. The idea is to find the method that
is used to generate default wifi access codes in classical wireless routers.

Algorithmic aspects:
   * the passphrase should be hexadecimal. It it therefore considered as part of a hash.
   * the search algorithm keeps a priority queue of expressions indexed by complexity

   * some expressions have multiple parameters and checking them all can take some time. So if not all parameters are checked, the expression is 
      kept in the pool.


                                                  +---- Input constant (Mac address, some numbers, strings, etc)
                                                  +---- Number (in different formats)
                                                  +---- Date (in different formats)
                                                  |
                       +------------- Combination of operations
                       |                          |
                       |         concatenation ---+ 
                       |             substring ---+ 
               Pool    |                                     Bruteforce engine
                |      |                                             |
                |      |                                       +-----+-----+
                |                                              |     |     |
                +---- Exp1,  state1, entropy1  ------------>  H2     H1    H3    (Hash functions)
                |                                              |     |     |
                +---- Exp2,  state2, entropy2                  +-----+-----+
                |                                                    |
                +---- Exp3,  state3, entropy3                     Checking (substring, hexa, etc)
                                                                     |
                                                                     +-----------> expression output

TODO
	- add all possible hash functions
	- add substring match

