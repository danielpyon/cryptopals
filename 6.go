package main

import (
	"fmt"
	b64 "encoding/base64"
	"io/ioutil"
	"strings"
	"math"
)

func ParseInputFile() []byte {
	data, err := ioutil.ReadFile("6.txt")
	if err != nil {
		panic("failed to read file!")
	}

	split := strings.Split(string(data), "\n")
	var result string
	for _, s := range split {
		result += s
	}

	dec, err := b64.StdEncoding.DecodeString(result)
	if err != nil {
		panic("invalid base64!")
	}

	return dec
}

// transpose("helloworld", 3) = hlod, eor, lwl
func Transpose(xs []byte, bins int) [][]byte {
	transpose := make([][]byte, bins)
	for i, x := range xs {
		transpose[i % bins] = append(transpose[i % bins], x)
	}
	return transpose
}


// InvTranspose([[a b c] [d e f] [g h i]]) = adgbehcfi
func InvTranspose(transpose []string) string {
	max := math.MinInt
	for _, str := range transpose {
		if len(str) > max {
			max = len(str)
		}
	}

	// idea: advance the "head" of each bin
	// current "head" of bin
	var ret string
	var i int
	for i = 0; i < max; i++ {
		// get the head of each bin
		var tmp string

		for j := 0; j < len(transpose); j++ {
			if i < len(transpose[j]) {
				tmp += string(transpose[j][i])
			} else {
				break
			}
		}
		ret += tmp
	}
	return ret
}

func main() {
	fmt.Println("challenge 6")
	ciphertext := ParseInputFile()

	/// introduction
	// the distance between x and y is the same as the distance between
	// Enc(x, key) and Enc(y, key), assuming x and y are adjacent, key-sized
	// chunks.
	// the reason we take hamming distance is because in english, two key-sized
	// chunks should not differ very much (max dist is from A to Z).
	// whereas uniformly random bytes will differ quite a bit.

	/// example:
	// "hel|lo |wor|ld", "abc"
	// "2x9|j10|9sf|ai"
	// "2x|9j|10|9s|fa|i" <- this is gonna find the distance between two unrelated strings

	// step 1: guess the key size
	key_size_to_dist := make(map[int]int)
	for key_size := 2; key_size <= 40; key_size++ {
		// average different blocks
		// first, make sure we have enough room for the blocks
		if key_size * 3 <= len(ciphertext) {
			first := ciphertext[:key_size]
			second := ciphertext[key_size:key_size*2]
			third := ciphertext[key_size*2:key_size*3]
		
			dist1, err := HammingDistance(first, second)
			if err != nil {
				panic("differing lengths of input")
			}

			dist2, err := HammingDistance(second, third)
			if err != nil {
				panic("differing lengths of input")
			}

			dist3, err := HammingDistance(first, third)
			if err != nil {
				panic("differing lengths of input")
			}
			
			avg := (dist1+dist2+dist3)/3

			// normalize result
			avg /= key_size

			key_size_to_dist[key_size] = avg
		}
	}

	// take the lowest n distances
	key_size_guesses := make([]int, 6)
	for i := 0; i < len(key_size_guesses); i++ {
		// find minimum value entry in map and delete it
		min_dist := math.MaxInt
		min_key := 0
		for k, v := range key_size_to_dist {
			if v < min_dist {
				min_dist = v
				min_key = k
			}
		}

		// remove min key
		delete(key_size_to_dist, min_key)

		// add to key size guesses
		key_size_guesses[i] = min_key
	}

	fmt.Println("most likely key sizes: ", key_size_guesses)

	// step 2:
	// now, we just do the same thing as in earlier attacks but split the string into chunks
	for _, key_size := range key_size_guesses {
		transpose := Transpose(ciphertext, key_size)
		decrypted_transpose := make([]string, len(transpose))
		var key []byte

		for i, chunk := range transpose {
			plaintext, _key := BreakSingleXORCipherWithKey(chunk)
			decrypted_transpose[i] = plaintext
			
			// append current byte of key to overall key
			key = append(key, _key)
		}

		fmt.Println("For key length: ", key_size)
		fmt.Println("and key: ", key)
		fmt.Println(InvTranspose(decrypted_transpose))
	}

	// answer:
	/*
For key length:  29
and key:  [84 101 114 109 105 110 97 116 111 114 32 120 58 32 66 114 105 110 103 32 116 104 101 32 110 111 105 115 101]
I'm back anD I'm ringin' the bell 
A rocKin' on the mike while the flY girls yell 
In ecstasy in tHe back of me 
Well that's myDJ Deshay cuttin' all them Zs 
Hittin' hard and the girlIes goin' crazy 
Vanilla's onthe mike, man I'm not lazy. *
I'm lettin' my drug kick in
It controls my mouth and I Begin 
To just let it flow, lEt my concepts go 
My posse'sto the side yellin', Go VaniLla Go! 

Smooth 'cause that'S the way I will be 
And if yOu don't give a damn, then 
WHy you starin' at me 
So get Off 'cause I control the stagE 
There's no dissin' allowed
I'm in my own phase 
The giRlies sa y they love me and tHat is ok 
And I can dance beTter than any kid n' play 

STage 2 -- Yea the one ya' wanNa listen to 
It's off my heaD so let the beat play througH 
So I can funk it up and maKe it sound good 
1-2-3 Yo --Knock on some wood 
For goodluck, I like my rhymes atrocIous 
SupercalafragilisticexpIalidocious 
I'm an effect anD that you can bet 
I can takE a fly girl and make her wet 

I'm like Samson -- Samsonto Delilah 
There's no denyiN', You can try to hang 
But You'll keep tryin' to get my Style 
Over and over, practicE makes perfect 
But not if yOu're a loafer. 

You'll get Nowhere, no place, no time, nO girls 
Soon -- Oh my God, hOmebody, you probably eat 
SpAghetti with a spoon! Come onand say it! 

VIP. Vanilla ICe yep, yep, I'm comin' hard Like a rhino 
Intoxicating soyou stagger like a wino 
So Punks stop trying and girl stOp cryin' 
Vanilla Ice is selLin' and you people are buyin 
'Cause why the freaks are Jockin' like Crazy Glue 
MoviN' and groovin' trying to sinG along 
All through the ghetTo groovin' this here song 
NOw you're amazed by the VIP pOsse. 

Steppin' so hard likea German Nazi 
Startled by tHe bases hittin' ground 
TherE's no trippin' on mine, I'm Just gettin' down 
SparkamatiC, I'm hangin' tight like a fAnatic 
You trapped me once aNd I thought that 
You might Have it 
So step down and lenD me your ear 
'89 in my time You, '90 is my year. 

You'Re weakenin' fast, YO! and I Can tell it 
Your body's gettIn' hot, so, so I can smell iT 
So don't be mad and don't Be sad 
'Cause the lyrics belOng to ICE, You can call me DAd 
You're pitchin' a fit, sostep back and endure 
Let thE witch doctor, Ice, do the dAnce to cure 
So come up closE and don't be square 
You waNna battle me -- Anytime, anyWhere 

You thought that I waS weak, Boy, you're dead wronG 
So come on, everybody and Sing this song 

Say -- Play That funky music Say, go whitE boy, go white boy go 
play That funky music Go white boy
                                   go white boy, go 
Lay down And boogie and play that funkY music till you die. 

Play That funky music Come on, ComE on, let me hear 
Play that Funky music white boy you sayit, say it 
Play that funky Music A little louder now 
PlAy that funky music, white boY Come on, Come on, Come on 
play that funky music 
	*/

}
