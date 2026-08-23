// Package solidity generates a Solidity verifier for a BN254 Groth16 circuit
// that draws more than one commitment.
//
// gnark's own generator supports at most one: with several commitments the
// verifier has to fold their proofs of knowledge, and the contract it emits
// neither derives the folding challenge nor sums the commitment points
// correctly. Proving, setup and off-chain verification are gnark's, untouched;
// only the contract is generated here.
package solidity

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"text/template"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	gnarksolidity "github.com/consensys/gnark/backend/solidity"
	"golang.org/x/crypto/sha3"
)

// templateVK is what the template reads. It is the exported part of gnark's
// verifying key, with Beta, Gamma and Delta already negated so the contract
// doesn't have to negate proof elements.
type templateVK struct {
	G1 struct {
		Alpha curve.G1Affine
		K     []curve.G1Affine
	}
	G2 struct {
		Beta, Gamma, Delta curve.G2Affine
	}
	CommitmentKeys               []pedersen.VerifyingKey
	PublicAndCommitmentCommitted [][]int
}

// ExportSolidity writes a Solidity verifier contract for vk to w.
//
// The proof it accepts is the one gnark's prover produces under
// [gnarksolidity.WithProverTargetSolidityVerifier], packed by [MarshalSolidity].
func ExportSolidity(vk *groth16.VerifyingKey, w io.Writer, exportOpts ...gnarksolidity.ExportOption) error {
	cfg, err := gnarksolidity.NewExportConfig(exportOpts...)
	if err != nil {
		return err
	}
	if cfg.HashToFieldFn == nil {
		// the default for solidity.WithProverTargetSolidityVerifier
		cfg.HashToFieldFn = sha3.NewLegacyKeccak256()
	}

	// The config carries a hash instance rather than a name, and the two
	// candidates are hard to tell apart by type, so hash the empty input and
	// compare digests.
	cfg.HashToFieldFn.Reset()
	var hashFnName string
	switch digest := cfg.HashToFieldFn.Sum(nil); {
	case bytes.Equal(digest, sha256.New().Sum(nil)):
		hashFnName = "sha256"
	case bytes.Equal(digest, sha3.NewLegacyKeccak256().Sum(nil)):
		hashFnName = "keccak256"
	default:
		return fmt.Errorf("unsupported hash function, only sha256 and legacy keccak256 are supported")
	}
	cfg.HashToFieldFn.Reset()

	// The contract hardcodes one shared PEDERSEN_G, reused by every
	// commitment's pairing check. That is only sound if all the commitment keys
	// were set up against the same G2 base point, which is what Setup does;
	// check it, since a violation would silently produce a wrong verifier.
	for i := 1; i < len(vk.CommitmentKeys); i++ {
		if vk.CommitmentKeys[i].G != vk.CommitmentKeys[0].G {
			return fmt.Errorf("commitment keys must share the same G2 base point to export a Solidity verifier")
		}
	}

	tmpl, err := template.New("").Funcs(helpers(hashFnName)).Parse(solidityTemplate)
	if err != nil {
		return err
	}

	var tvk templateVK
	tvk.G1.Alpha, tvk.G1.K = vk.G1.Alpha, vk.G1.K
	tvk.G2.Beta.Neg(&vk.G2.Beta)
	tvk.G2.Gamma.Neg(&vk.G2.Gamma)
	tvk.G2.Delta.Neg(&vk.G2.Delta)
	tvk.CommitmentKeys = vk.CommitmentKeys
	tvk.PublicAndCommitmentCommitted = vk.PublicAndCommitmentCommitted

	return tmpl.Execute(w, struct {
		Cfg gnarksolidity.ExportConfig
		Vk  templateVK
	}{Cfg: cfg, Vk: tvk})
}

func helpers(hashFnName string) template.FuncMap {
	return template.FuncMap{
		"sum": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"mul": func(a, b int) int { return a * b },
		"hex": func(i int) string { return fmt.Sprintf("0x%x", i) },
		"intRange": func(max int) []int {
			out := make([]int, max)
			for i := range out {
				out[i] = i
			}
			return out
		},
		"fpstr": func(x fp.Element) string {
			bv := new(big.Int)
			x.BigInt(bv)
			return bv.String()
		},
		"hashFnName": func() string { return hashFnName },
	}
}

// MarshalSolidity packs a proof the way the generated verifyProof expects:
//
//	Ar.X (32) | Ar.Y (32) | Bs.X1 (32) | Bs.X0 (32) | Bs.Y1 (32) | Bs.Y0 (32) | Krs.X (32) | Krs.Y (32)
//	[Commitment_0.X (32) | Commitment_0.Y (32) | ... | PoK.X (32) | PoK.Y (32)]
func MarshalSolidity(proof *groth16.Proof) []byte {
	var buf bytes.Buffer
	if _, err := proof.WriteRawTo(&buf); err != nil {
		panic(err)
	}
	raw := buf.Bytes()

	// WriteRawTo emits Ar(64) | Bs(128) | Krs(64) | len(4) | Commitments(N×64) | PoK(64);
	// the contract wants the same without the 4-byte slice length prefix.
	const base = 8 * fp.Bytes
	if len(proof.Commitments) == 0 {
		return raw[:base]
	}
	return append(append(make([]byte, 0, len(raw)-4), raw[:base]...), raw[base+4:]...)
}
