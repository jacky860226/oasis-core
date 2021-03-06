// Package ledger provides a Ledger backed signer.
package ledger

import (
	"errors"
	"fmt"
	"io"

	ledger "github.com/zondax/ledger-go"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	ledgerCommon "github.com/oasisprotocol/oasis-core/go/common/ledger"
)

const (
	// SignerName is the name used to identify the Ledger backed signer.
	SignerName = "ledger"

	// SignerPathCoinType is set to 474, the number associated with Oasis ROSE.
	SignerPathCoinType uint32 = 474
	// SignerPathAccount is the account index used to sign transactions.
	SignerPathAccount uint32 = 0
	// SignerPathChange indicates an external chain.
	SignerPathChange uint32 = 0
)

var (
	_ signature.SignerFactoryCtor = NewFactory
	_ signature.SignerFactory     = (*Factory)(nil)
	_ signature.Signer            = (*Signer)(nil)

	// SignerEntityDerivationRootPath is the BIP-0032 path prefix used for generating
	// an Entity signer.
	SignerEntityDerivationRootPath = []uint32{
		ledgerCommon.PathPurposeBIP44,
		SignerPathCoinType,
		SignerPathAccount,
		SignerPathChange,
	}
	// SignerConsensusDerivationRootPath is the derivation path prefix used for
	// generating a consensus signer.
	SignerConsensusDerivationRootPath = []uint32{
		ledgerCommon.PathPurposeOther,
		SignerPathCoinType,
		ledgerCommon.PathSubPurposeConsensus,
		SignerPathAccount,
	}

	roleDerivationRootPaths = map[signature.SignerRole][]uint32{
		signature.SignerEntity:    SignerEntityDerivationRootPath,
		signature.SignerConsensus: SignerConsensusDerivationRootPath,
	}

	// NOTE: The 0x6986 ISO 7816 error code is returned by the Oasis Ledger App
	// iff when a user rejects the transaction on the Ledger device.
	ledgerRejectTxErrorMsg = ledger.ErrorMessage(0x6986)
)

// Factory is a Ledger backed SignerFactory.
type Factory struct {
	roles   []signature.SignerRole
	address string
	index   uint32
}

// FactoryConfig is the config necessary to create a Factory for Ledger Signers
type FactoryConfig struct {
	Address string
	Index   uint32
}

// NewFactory creates a new factory with the specified roles.
func NewFactory(config interface{}, roles ...signature.SignerRole) (signature.SignerFactory, error) {
	ledgerConfig, ok := config.(*FactoryConfig)
	if !ok {
		return nil, fmt.Errorf("invalid Ledger signer configuration provided")
	}
	return &Factory{
		roles:   append([]signature.SignerRole{}, roles...),
		address: ledgerConfig.Address,
		index:   ledgerConfig.Index,
	}, nil
}

// EnsureRole ensures that the SignatureFactory is configured for the given
// role.
func (fac *Factory) EnsureRole(role signature.SignerRole) error {
	for _, v := range fac.roles {
		if v == role {
			return nil
		}
	}
	return signature.ErrRoleMismatch
}

// Generate has the same functionality as Load, since all keys are generated
// on the Ledger device.
func (fac *Factory) Generate(role signature.SignerRole, _rng io.Reader) (signature.Signer, error) {
	return fac.Load(role)
}

// Load will create a Signer backed by a Ledger device by searching for
// a device with the expected address. If no address is provided, this will
// created a Signer with the first Ledger device it finds.
// The only role allowed is SignerEntity.
func (fac *Factory) Load(role signature.SignerRole) (signature.Signer, error) {
	pathPrefix, ok := roleDerivationRootPaths[role]
	if !ok {
		return nil, fmt.Errorf("role %d is not supported when using the Ledger backed signer", role)
	}
	device, err := ledgerCommon.ConnectToDevice(fac.address, append(pathPrefix, fac.index))
	if err != nil {
		return nil, err
	}

	return &Signer{device, append(pathPrefix, fac.index), nil}, nil
}

// Signer is a Ledger backed Signer.
type Signer struct {
	device    *ledgerCommon.Device
	path      []uint32
	publicKey *signature.PublicKey
}

// Public retrieves the public key from the Ledger device.
func (s *Signer) Public() signature.PublicKey {
	if s.publicKey != nil {
		return *s.publicKey
	}

	var pubKey signature.PublicKey
	retrieved, err := s.device.GetPublicKeyEd25519(s.path)
	if err != nil {
		panic(fmt.Errorf("failed to retrieve public key from device: %w", err))
	}
	copy(pubKey[:], retrieved)
	s.publicKey = &pubKey
	return pubKey
}

// ContextSign generates a signature with the private key over the context and
// message.
func (s *Signer) ContextSign(context signature.Context, message []byte) ([]byte, error) {
	preparedContext, err := signature.PrepareSignerContext(context)
	if err != nil {
		return nil, err
	}
	signature, err := s.device.SignEd25519(s.path, preparedContext, message)
	switch {
	case err == nil:
		return signature, nil
	// XXX: At the moment, ledger-go doesn't use proper Go error semantics and
	// doesn't expose errors as variables so we can't compare them directly with
	// errors.Is().
	case err.Error() == ledgerRejectTxErrorMsg:
		// Replace Ledger's raw APDU error with a more descriptive one.
		return nil, errors.New("transaction was rejected on Ledger device")
	default:
		return nil, err
	}
}

// String returns the address of the account on the Ledger device.
func (s *Signer) String() string {
	return fmt.Sprintf("[ledger signer: %s]", s.Public())
}

// Reset tears down the Signer.
func (s *Signer) Reset() {
	s.device.Close()
}
