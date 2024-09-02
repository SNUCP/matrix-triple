package hpbfv

import (
	"math/big"

	"hp-bfv/rlwe"
)

func MustBigFromDecimal(dec string) *big.Int {
	bigInt, ok := new(big.Int).SetString(dec, 10)
	if !ok {
		panic("cannot parse decimal string to big.Int")
	}
	return bigInt
}

var (
	HPN14D13T128 = ParametersLiteral{
		LogN: 14,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffd08001,
			0x1fffffffffcf8001, 0x1fffffffffc80001,
			0x1fffffffffb40001,
		}, // 61 * 7 = 427
		QMul: []uint64{
			0x1fffffffffab0001, 0x1fffffffffa10001,
			0x1fffffffff998001, 0x1fffffffff978001,
			0x1fffffffff8a8001, 0x1fffffffff7c8001,
			0x1fffffffff608001,
		},

		Sigma: rlwe.DefaultSigma,

		B: MustBigFromDecimal("18446744073709548544"), // 2^64 - 3072
		D: 1 << 13,
		G: big.NewInt(27), // 3^3
	}

	HPN14D12T256 = ParametersLiteral{
		LogN: 14,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffd08001,
			0x1fffffffffcf8001, 0x1fffffffffc80001,
			0x1fffffffffb40001,
		}, // 61 * 7 = 427
		QMul: []uint64{
			0x1fffffffffab0001, 0x1fffffffffa10001,
			0x1fffffffff998001, 0x1fffffffff978001,
			0x1fffffffff8a8001, 0x1fffffffff7c8001,
			0x1fffffffff608001,
		},

		Sigma: rlwe.DefaultSigma,

		B: MustBigFromDecimal("18446744073709551552"), // 2^64 - 64
		D: 1 << 12,
		G: big.NewInt(48828125), // 5^11
	}

	HPN14D11T512 = ParametersLiteral{
		LogN: 14,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffd08001,
			0x1fffffffffcf8001, 0x1fffffffffc80001,
			0x1fffffffffb40001,
		}, // 61 * 7 = 427
		QMul: []uint64{
			0x1fffffffffab0001, 0x1fffffffffa10001,
			0x1fffffffff998001, 0x1fffffffff978001,
			0x1fffffffff8a8001, 0x1fffffffff7c8001,
			0x1fffffffff608001,
		},

		Sigma: rlwe.DefaultSigma,

		B: MustBigFromDecimal("18446744073709551188"), // 2^64 - 428
		D: 1 << 11,
		G: big.NewInt(27), // 3^3
	}

	HPN14D10T1024 = ParametersLiteral{
		LogN: 14,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffd08001,
			0x1fffffffffcf8001, 0x1fffffffffc80001,
			0x1fffffffffb40001,
		}, // 61 * 7 = 427
		QMul: []uint64{
			0x1fffffffffab0001, 0x1fffffffffa10001,
			0x1fffffffff998001, 0x1fffffffff978001,
			0x1fffffffff8a8001, 0x1fffffffff7c8001,
			0x1fffffffff608001,
		},

		Sigma: rlwe.DefaultSigma,

		B: MustBigFromDecimal("18446744073709551608"), // 2^64 - 8
		D: 1 << 10,
		G: big.NewInt(7625597484987), // 3^27
	}

	HPN14D9T2048 = ParametersLiteral{
		LogN: 14,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffd08001,
			0x1fffffffffcf8001, 0x1fffffffffc80001,
			0x1fffffffffb40001,
		}, // 61 * 7 = 427
		QMul: []uint64{
			0x1fffffffffab0001, 0x1fffffffffa10001,
			0x1fffffffff998001, 0x1fffffffff978001,
			0x1fffffffff8a8001, 0x1fffffffff7c8001,
			0x1fffffffff608001,
		},

		Sigma: rlwe.DefaultSigma,

		B: MustBigFromDecimal("18446744073709551594"), // 2^64 - 22
		D: 1 << 9,
		G: big.NewInt(5), // 5^1
	}

	HPN14D8T4096 = ParametersLiteral{
		LogN: 14,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffd08001,
			0x1fffffffffcf8001, 0x1fffffffffc80001,
			0x1fffffffffb40001,
		}, // 61 * 7 = 427
		QMul: []uint64{
			0x1fffffffffab0001, 0x1fffffffffa10001,
			0x1fffffffff998001, 0x1fffffffff978001,
			0x1fffffffff8a8001, 0x1fffffffff7c8001,
			0x1fffffffff608001,
		},

		Sigma: rlwe.DefaultSigma,

		B: MustBigFromDecimal("18446744073709551560"), // 2^64 - 56
		D: 1 << 8,
		G: MustBigFromDecimal("328256967394537077627"), // 3^43
	}

	HPN13D10T128 = ParametersLiteral{
		LogN: 13,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffd08001,
		}, // 61 * 4 = 244
		QMul: []uint64{
			0x1fffffffffab0001, 0x1fffffffffa10001,
			0x1fffffffff998001, 0x1fffffffff978001,
		},

		Sigma: rlwe.DefaultSigma,

		B: big.NewInt(65340), // 2^16 - 196
		D: 1 << 10,
		G: big.NewInt(823543), // 7^7
	}

	HPN13D9T256 = ParametersLiteral{
		LogN: 13,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffd08001,
		}, // 61 * 4 = 244
		QMul: []uint64{
			0x1fffffffffab0001, 0x1fffffffffa10001,
			0x1fffffffff998001, 0x1fffffffff978001,
		},

		Sigma: rlwe.DefaultSigma,

		B: big.NewInt(65514), // 2^16 - 22
		D: 1 << 9,
		G: big.NewInt(762939453125), // 5^17
	}

	HPN13D8T512 = ParametersLiteral{
		LogN: 13,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffd08001,
		}, // 61 * 4 = 244
		QMul: []uint64{
			0x1fffffffffab0001, 0x1fffffffffa10001,
			0x1fffffffff998001, 0x1fffffffff978001,
		},

		Sigma: rlwe.DefaultSigma,

		B: big.NewInt(65464), // 2^16 - 72
		D: 1 << 8,
		G: big.NewInt(5), // 5
	}

	HPN13D7T1024 = ParametersLiteral{
		LogN: 13,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffd08001,
		}, // 61 * 4 = 244
		QMul: []uint64{
			0x1fffffffffab0001, 0x1fffffffffa10001,
			0x1fffffffff998001, 0x1fffffffff978001,
		},

		Sigma: rlwe.DefaultSigma,

		B: big.NewInt(65508), // 2^16 - 28
		D: 1 << 7,
		G: big.NewInt(5), // 5
	}

	HPN13D6T2048 = ParametersLiteral{
		LogN: 13,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffd08001,
		}, // 61 * 4 = 244
		QMul: []uint64{
			0x1fffffffffab0001, 0x1fffffffffa10001,
			0x1fffffffff998001, 0x1fffffffff978001,
		},

		Sigma: rlwe.DefaultSigma,

		B: big.NewInt(65346), // 2^16 - 190
		D: 1 << 6,
		G: MustBigFromDecimal("34211388289180104270598866779538968048834520065344623333912799899653102604635268590982377645559608936309814453125"), // 5^161
	}

	HPN13D5T4096 = ParametersLiteral{
		LogN: 13,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffd08001,
		}, // 61 * 4 = 244
		QMul: []uint64{
			0x1fffffffffab0001, 0x1fffffffffa10001,
			0x1fffffffff998001, 0x1fffffffff978001,
		},

		Sigma: rlwe.DefaultSigma,

		B: big.NewInt(65248), // 2^16 - 288
		D: 1 << 5,
		G: MustBigFromDecimal("13289078263368535010350719491824534628404827374597126975388693711018284879396957772210874852435860862184279107707"), // 3^235
	}

	PN15T128 = ParametersLiteral{
		LogN: 15,

		Q: []uint64{
			0x1fffffffffe10001, 0x1fffffffffe00001,
			0x1fffffffffdd0001, 0x1fffffffffc80001,
			0x1fffffffffb40001, 0x1fffffffffab0001,
			0x1fffffffffa10001, 0x1fffffffff500001,
			0x1fffffffff420001, 0x1fffffffff380001,
			0x1fffffffff090001, 0x1fffffffff000001,
		}, // 61 * 12 = 732
		QMul: []uint64{
			0x1ffffffffef00001, 0x1ffffffffeed0001,
			0x1ffffffffee80001, 0x1ffffffffeb40001,
			0x1ffffffffe7f0001, 0x1ffffffffe780001,
			0x1ffffffffe6f0001, 0x1ffffffffe600001,
			0x1ffffffffe4c0001, 0x1ffffffffdfd0001,
			0x1ffffffffdf40001, 0x1ffffffffdef0001,
		},

		B: MustBigFromDecimal("340282366920938463463374607431759953920"), // 2^128 - 8257536
		D: 1 << 15,
		G: big.NewInt(3),
	}

	PN16T256 = ParametersLiteral{
		LogN: 16,

		Q: []uint64{
			0x1fffffffffe00001, 0x1fffffffffc80001,
			0x1fffffffffb40001, 0x1fffffffff500001,
			0x1fffffffff420001, 0x1fffffffff380001,
			0x1fffffffff000001, 0x1ffffffffef00001,
			0x1ffffffffee80001, 0x1ffffffffeb40001,
			0x1ffffffffe780001, 0x1ffffffffe600001,
			0x1ffffffffe4c0001, 0x1ffffffffdf40001,
			0x1ffffffffdce0001, 0x1ffffffffdb20001,
			0x1ffffffffdac0001, 0x1ffffffffda40001,
			0x1ffffffffd7a0001, 0x1ffffffffc680001,
		}, // 61 * 20 = 1220
		QMul: []uint64{
			0x1ffffffffc000001, 0x1ffffffffb880001,
			0x1ffffffffb7c0001, 0x1ffffffffb300001,
			0x1ffffffffb1e0001, 0x1ffffffffb1c0001,
			0x1ffffffffb0a0001, 0x1ffffffffaf20001,
			0x1ffffffffadc0001, 0x1ffffffffa6a0001,
			0x1ffffffffa560001, 0x1ffffffffa400001,
			0x1ffffffffa140001, 0x1ffffffff9de0001,
			0x1ffffffff9d80001, 0x1ffffffff9d20001,
			0x1ffffffff9ce0001, 0x1ffffffff9140001,
			0x1ffffffff8ac0001, 0x1ffffffff8a80001,
		},

		B: MustBigFromDecimal("115792089237316195423570985008687907853269984665640564039457584007913121120256"), // 2^256 - 8519680
		D: 1 << 16,
		G: big.NewInt(5),
	}

	PN17T512 = ParametersLiteral{
		LogN: 17,

		Q: []uint64{
			0x1fffffffffe00001, 0x1fffffffffc80001,
			0x1fffffffffb40001, 0x1fffffffff500001,
			0x1fffffffff380001, 0x1fffffffff000001,
			0x1ffffffffef00001, 0x1ffffffffee80001,
			0x1ffffffffeb40001, 0x1ffffffffe780001,
			0x1ffffffffe600001, 0x1ffffffffe4c0001,
			0x1ffffffffdf40001, 0x1ffffffffdac0001,
			0x1ffffffffda40001, 0x1ffffffffc680001,
			0x1ffffffffc000001, 0x1ffffffffb880001,
			0x1ffffffffb7c0001, 0x1ffffffffb300001,
			0x1ffffffffb1c0001, 0x1ffffffffadc0001,
			0x1ffffffffa400001, 0x1ffffffffa140001,
			0x1ffffffff9d80001, 0x1ffffffff9140001,
			0x1ffffffff8ac0001, 0x1ffffffff8a80001,
			0x1ffffffff81c0001, 0x1ffffffff7800001,
			0x1ffffffff7680001, 0x1ffffffff7080001,
			0x1ffffffff6c80001, 0x1ffffffff6140001,
			0x1ffffffff5f40001, 0x1ffffffff5700001,
			0x1ffffffff4bc0001,
		}, // 61 * 37 = 2257
		QMul: []uint64{
			0x1ffffffff4380001, 0x1ffffffff3240001,
			0x1ffffffff2dc0001, 0x1ffffffff1a40001,
			0x1ffffffff11c0001, 0x1ffffffff0fc0001,
			0x1ffffffff0d80001, 0x1ffffffff0c80001,
			0x1ffffffff08c0001, 0x1fffffffefd00001,
			0x1fffffffef9c0001, 0x1fffffffef600001,
			0x1fffffffeef40001, 0x1fffffffeed40001,
			0x1fffffffeed00001, 0x1fffffffeebc0001,
			0x1fffffffed540001, 0x1fffffffed440001,
			0x1fffffffed2c0001, 0x1fffffffed200001,
			0x1fffffffec940001, 0x1fffffffec6c0001,
			0x1fffffffebe80001, 0x1fffffffebac0001,
			0x1fffffffeba40001, 0x1fffffffeb4c0001,
			0x1fffffffeb280001, 0x1fffffffea780001,
			0x1fffffffea440001, 0x1fffffffe9f40001,
			0x1fffffffe97c0001, 0x1fffffffe9300001,
			0x1fffffffe8d00001, 0x1fffffffe8400001,
			0x1fffffffe7cc0001, 0x1fffffffe7bc0001,
			0x1fffffffe7a80001,
		},

		B: MustBigFromDecimal("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433648987209728"), // 2^512 - 18874368
		D: 1 << 17,
		G: big.NewInt(3),
	}

	PN18T1024 = ParametersLiteral{
		LogN: 18,

		Q: []uint64{
			0x1fffffffffe00001, 0x1fffffffffc80001,
			0x1fffffffff500001, 0x1fffffffff380001,
			0x1fffffffff000001, 0x1ffffffffef00001,
			0x1ffffffffee80001, 0x1ffffffffe780001,
			0x1ffffffffe600001, 0x1ffffffffc680001,
			0x1ffffffffc000001, 0x1ffffffffb880001,
			0x1ffffffffb300001, 0x1ffffffffa400001,
			0x1ffffffff9d80001, 0x1ffffffff8a80001,
			0x1ffffffff7800001, 0x1ffffffff7680001,
			0x1ffffffff7080001, 0x1ffffffff6c80001,
			0x1ffffffff5700001, 0x1ffffffff4380001,
			0x1ffffffff0d80001, 0x1ffffffff0c80001,
			0x1fffffffefd00001, 0x1fffffffef600001,
			0x1fffffffeed00001, 0x1fffffffed200001,
			0x1fffffffebe80001, 0x1fffffffeb280001,
			0x1fffffffea780001, 0x1fffffffe9300001,
			0x1fffffffe8d00001, 0x1fffffffe8400001,
			0x1fffffffe7a80001, 0x1fffffffe7600001,
			0x1fffffffe7500001, 0x1fffffffe6d80001,
			0x1fffffffe6000001, 0x1fffffffe5a00001,
			0x1fffffffe2b00001, 0x1fffffffe2680001,
			0x1fffffffe0480001, 0x1fffffffdfd00001,
			0x1fffffffdf700001, 0x1fffffffdef80001,
			0x1fffffffdea80001, 0x1fffffffde680001,
			0x1fffffffde000001, 0x1fffffffddd80001,
			0x1fffffffddd00001, 0x1fffffffdd780001,
			0x1fffffffdcb80001, 0x1fffffffdc380001,
			0x1fffffffdba80001, 0x1fffffffdb380001,
			0x1fffffffda600001, 0x1fffffffda180001,
			0x1fffffffd9700001, 0x1fffffffd9680001,
			0x1fffffffd9080001, 0x1fffffffd8c80001,
			0x1fffffffd8800001, 0x1fffffffd7b80001,
			0x1fffffffd6f80001, 0x1fffffffd5900001,
			0x1fffffffd5480001, 0x1fffffffd5380001,
			0x1fffffffd3800001, 0x1fffffffd3100001,
			0x1fffffffd2980001,
		}, // 61 * 71 = 4331
		QMul: []uint64{
			0x1fffffffd2780001, 0x1fffffffd1a00001,
			0x1fffffffd1700001, 0x1fffffffd1580001,
			0x1fffffffd0f80001, 0x1fffffffcfa80001,
			0x1fffffffce400001, 0x1fffffffcdb80001,
			0x1fffffffcbc00001, 0x1fffffffca280001,
			0x1fffffffc9e00001, 0x1fffffffc8c00001,
			0x1fffffffc7f80001, 0x1fffffffc6380001,
			0x1fffffffc5a00001, 0x1fffffffc5900001,
			0x1fffffffc4100001, 0x1fffffffc4080001,
			0x1fffffffc2f00001, 0x1fffffffc2c00001,
			0x1fffffffc2580001, 0x1fffffffc1e80001,
			0x1fffffffbe880001, 0x1fffffffbe200001,
			0x1fffffffbd980001, 0x1fffffffbd800001,
			0x1fffffffbca80001, 0x1fffffffbc880001,
			0x1fffffffbbe00001, 0x1fffffffbb700001,
			0x1fffffffbb200001, 0x1fffffffbaa80001,
			0x1fffffffba300001, 0x1fffffffb9e80001,
			0x1fffffffb7c00001, 0x1fffffffb6c00001,
			0x1fffffffb5b80001, 0x1fffffffb5a00001,
			0x1fffffffb5280001, 0x1fffffffb4c00001,
			0x1fffffffb4780001, 0x1fffffffb2800001,
			0x1fffffffb2580001, 0x1fffffffb2380001,
			0x1fffffffb1e00001, 0x1fffffffb1000001,
			0x1fffffffb0f00001, 0x1fffffffb0580001,
			0x1fffffffafe00001, 0x1fffffffad700001,
			0x1ffffffface00001, 0x1fffffffacd00001,
			0x1fffffffac500001, 0x1fffffffac200001,
			0x1fffffffaba80001, 0x1fffffffa9a00001,
			0x1fffffffa9200001, 0x1fffffffa7f00001,
			0x1fffffffa7b80001, 0x1fffffffa7300001,
			0x1fffffffa7180001, 0x1fffffffa5200001,
			0x1fffffffa4780001, 0x1fffffffa4280001,
			0x1fffffffa3d00001, 0x1fffffffa3200001,
			0x1fffffffa3100001, 0x1fffffffa2c80001,
			0x1fffffffa2980001, 0x1fffffffa2300001,
			0x1fffffffa1d00001,
		},

		B: MustBigFromDecimal("179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624112463872"), // 2^1024 - 111673344
		D: 1 << 18,
		G: big.NewInt(3),
	}
)
