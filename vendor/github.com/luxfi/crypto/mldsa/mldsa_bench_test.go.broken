package mldsa

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func BenchmarkMLDSA44(b *testing.B) {
	benchmarkMLDSA(b, MLDSA44)
}

func BenchmarkMLDSA65(b *testing.B) {
	benchmarkMLDSA(b, MLDSA65)
}

func BenchmarkMLDSA87(b *testing.B) {
	benchmarkMLDSA(b, MLDSA87)
}

func benchmarkMLDSA(b *testing.B, mode Mode) {
	message := make([]byte, 32)
	rand.Read(message)

	b.Run("GenerateKey", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := GenerateKey(rand.Reader, mode)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	priv, err := GenerateKey(rand.Reader, mode)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("Sign", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := priv.Sign(rand.Reader, message, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	sig, err := priv.Sign(rand.Reader, message, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("Verify", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			valid := priv.PublicKey.Verify(message, sig, nil)
			if !valid {
				b.Fatal("verification failed")
			}
		}
	})

	b.Run("Serialize", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = priv.Bytes()
			_ = priv.PublicKey.Bytes()
		}
	})

	privBytes := priv.Bytes()
	pubBytes := priv.PublicKey.Bytes()

	b.Run("Deserialize", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := PrivateKeyFromBytes(privBytes, mode)
			if err != nil {
				b.Fatal(err)
			}
			_, err = PublicKeyFromBytes(pubBytes, mode)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Batch verification benchmark
func BenchmarkMLDSABatchVerify(b *testing.B) {
	modes := []struct {
		name string
		mode Mode
	}{
		{"MLDSA44", MLDSA44},
		{"MLDSA65", MLDSA65},
		{"MLDSA87", MLDSA87},
	}

	for _, m := range modes {
		b.Run(m.name, func(b *testing.B) {
			// Generate multiple signatures
			numSigs := 10
			messages := make([][]byte, numSigs)
			signatures := make([][]byte, numSigs)
			
			priv, _ := GenerateKey(rand.Reader, m.mode)
			for i := 0; i < numSigs; i++ {
				messages[i] = make([]byte, 32)
				rand.Read(messages[i])
				signatures[i], _ = priv.Sign(rand.Reader, messages[i], nil)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Verify all signatures
				for j := 0; j < numSigs; j++ {
					if !priv.PublicKey.Verify(messages[j], signatures[j], nil) {
						b.Fatal("verification failed")
					}
				}
			}
		})
	}
}

// Different message sizes
func BenchmarkMLDSAMessageSizes(b *testing.B) {
	sizes := []int{32, 64, 128, 256, 512, 1024}
	priv, _ := GenerateKey(rand.Reader, MLDSA65)

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size%d", size), func(b *testing.B) {
			message := make([]byte, size)
			rand.Read(message)
			
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sig, _ := priv.Sign(rand.Reader, message, nil)
				if !priv.PublicKey.Verify(message, sig, nil) {
					b.Fatal("verification failed")
				}
			}
		})
	}
}