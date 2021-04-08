
# KIV/BIT task 04 - Knapsack encryption algorithm

## Compilation

The compilation process is done through the `make`command that's supposed to be executed in the root folder of the project structure. Once the process has completed, a file called `knapsack` will be generated. This file represents the executable file of the application.

## Execution

### help
```
> ./knapsack --help
KIV/BIT task 4 - knapsack encryption/decryption
Usage:
  ./knapsack <input> <p> <q> [OPTION...]

  -v, --verbose          print out info as the program proceeds
  -o, --output arg       name of the output file (default: output.txt)
  -b, --binary           the input file will be treated as a binary file
  -k, --private-key arg  file containing the private key (default: 
                         keys/private_key_1.txt)
  -l, --public-key arg   file containing the private key (default: 
                         public_key.txt)
  -p, --print            print out the binary data as well as the decrypted 
                         text
  -d, --debug            print out step-by-step the process of 
                         encryption/decryption
  -x, --hex-padding arg  set number of digits to be printed out in a 
                         hexadecimal format (default: 5)
  -h, --help             print help
>
```
### input
The program takes three compulsory parameters which happen to be the `input file`, and the values `p` and `q` that make up a part of a private key. However, the user should specify a `private key file` as well. By default, `keys/private_key_1.txt`is used as a private key used to generate a public key.

#### input file
There's no limitation as to what type of the input file should be. However, in case of a binary file, the user should use the `-b` option so the program can treat it accordingly.

### private key
The private key should be represented by a `txt` file containing numbers separated by a semicolon `;`.
Additionally, the sequence of numbers should be super-increasing [https://en.wikipedia.org/wiki/Superincreasing_sequence](). The user has the option to specify a private key using the `-k` option when running the program.

#### example of a private key file (a super-increasing sequence)
```
51,78,198,619,1111,3255,7596,13533
```
### values `p` and `q`
These two values must follow two rules. First of all, the numbers are supposed to be relatively prime [https://en.wikipedia.org/wiki/Coprime_integers](). And secondly, the value `q` must be greater than the sum of all values making up a private key.
### output
As the first step, the program will generate a public key off the private one using the values `p` and `q`. The public key will be stored by default in `public_key.txt`, but it could be changed using the `-l` option. The formula used for generating a public key is `public[i] = (p * private[i]) % q`. This key is supposed to be sent out to other people so they can encrypt data in way that we're the only ones who will be able to decrypt it afterwards.

After the program has been run, a file called `output.txt` will be created containing the required output. The file is consists of three lines in total with the following meanings.
```
8C 71 E8 E8 DB 20 72 DB 07 E8 60 31 # encrypted data in HEX
48 65 6C 6C 6F 20 57 6F 72 6C 64 21 # decrypted data in HEX
Hello World!			    # decrypted data in ASCII (if it's a text file)
```
However, the last line differs by the type of input file. If a text file has been used, the third line will hold the encrypted ASCII text, which should match the original file.
In the case of a binary file, the third line displays a note referring to another binary file, which has been generated after decryption. This file has a prefix of  `knapsack_`, and the rest matches the name of the input file.
```
INFO: The decrypted content of the file can be found in 'knapsack_dwarf_small.bmp'
```
### Examples of execution
```
./knapsack data/input.txt 43 218 -pv -x 4
./knapsack data/input.txt 43 218 -pv -x 4
./knapsack data/dwarf_small.bmp 43 101293 -bv -x 5 --public-key pub.txt
```
## Knapsack encryption algorithm
### encryption
The process of encryption works the following way. 
1.	The private key is read off the file making all the conditions are satisfied - the sequence must be super-increasing, the values `p` and `q` must be relativity prime, and lastly, the value `q` must be greater than the sum of all the values in the private key.
2.	A public key (another sequence) is generated using the following formula `public[i] = (p * private[i]) % q`. The public key is used in the next step for encrypting the data.
3.	The data of the input file is treated as bits. The total number of values in the private key determines the size of one block of the data (number of bits). The input data will be then split up into blocks of this size where each block is looked at as a sequence of bits. For example, if the number of values in the private key is 8, then a block of data may look like `10110010`. Now, having the public key, we will go over the block of data and for each bit set to 1, we will add the corresponding value (at the same position) of the public key to the final sum. The final sum then represents one piece of data that has been encrypted.
#### example of encryption
```
p = 43
q = 218
private key = [3,8,15,35,155]
one block of data = [10010]
----------------
public key = [129,126,209,197,125]
----------------
sum = 0
1 - sum = sum + 129
0 -
0 -
1 - sum = sum + 197
0 -
----------------
encrypted block of data = 326 (146 HEX)
```
### decryption
For the decryption process, we can only use the values `p` and `q` along with the private key itself.
1. The first step is to calculate the value `p^(-1)` which plays a crucial role in terms of decryption. The value is calculated by the following formula `p * p^(-1) mod q = 1`. To work this out, we can use the extended version of the Euclidean algorithm [https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm]().
#### the implementation of the Extended Euclidean algorithm
```c++
struct xgdc_values_t {
    // a*x + b*y = gdc(a,b)
    int d; // gdc(a,b)
    int x; 
    int y;
};

xgdc_values_t xgdc(int a, int b) {
    if (b == 0)
        return {a, 1, 0};
    else {
        auto vals = xgdc(b, a % b);
        return {vals.d, vals.y, vals.x - vals.y * (a / b)};
    }
}

int getInvertedP(int p, int q) {
    auto values = xgdc(p, q);
    if (values.x >= 0)
        return values.x;
    return q + values.x;
}
```
2.  Once we've worked out `p^(-1)`, we will iterate of the the encrypted data and on each block, we will apply the following formula `block[i] * p^(-1) mod q`.
3. Finally, using the private key we'll break each value into bits  which should match the original plain text. Let's assume the formula above gave us the number `43`. We'll go over the private key in a decreasing order and for each value of the key, we will write down `1` if it fits into the current value (43) and `0` if it doesn't. If it does fit, will subtract it from the current value before move on to another position within the private key.
#### example of decryption
```
let's assumte the formula above produced number the 43.
private key = [3,8,15,35,155]
----------------
sum = 43

155 - doesn't fit -> 0
35  - does fit    -> 1 (sum = sum - 35 = 8)
15  - doesn't fit -> 0
8   - does fit    -> 1 (sum = sum - 8 = 0) we're done :)
3   - doesn't fit -> 0
----------------
decrypted data = 01010
```
## Implementation
### multiplication of large numbers
Since the process of multiplying two numbers can produce a number that could overflow the `int` data type, a modified algorithm for  multiplication was implemented. The time complexity of this algorithm is `O(log n)`.
```c++
// (a * b) % c
int mult(int a, int b, int c) {
    if (a == 0 || b == 0)
        return 0;
    if (a == 1)
        return b;
    if (b == 1)
        return a;

    int a2 = mult(a, b / 2, c);

    if ((b & 1) == 0) {
        return (a2 + a2) % c;
    } else {
        return ((a % c) + (a2 + a2)) % c;
    }
}
```