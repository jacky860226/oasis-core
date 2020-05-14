package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/node"
	abciAPI "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	tmcrypto "github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

var (
	nodeSigner       = memorySigner.NewTestSigner("consensus/tendermint/apps/registry/state: node signer")
	consensusSigner1 = memorySigner.NewTestSigner("consensus/tendermint/apps/registry/state: consensus signer 1")
	consensusSigner2 = memorySigner.NewTestSigner("consensus/tendermint/apps/registry/state: consensus signer 2")
	p2pSigner1       = memorySigner.NewTestSigner("consensus/tendermint/apps/registry/state: p2p signer 1")
	p2pSigner2       = memorySigner.NewTestSigner("consensus/tendermint/apps/registry/state: p2p signer 2")
)

func mustMultiSignNode(t *testing.T, n *node.Node) *node.MultiSignedNode {
	signed, err := node.MultiSignNode([]signature.Signer{nodeSigner}, registry.RegisterNodeSignatureContext, n)
	require.NoError(t, err, "MultiSignNode")
	return signed
}

func TestNodeUpdate(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock, now)
	defer ctx.Close()

	s := NewMutableState(ctx.State())

	// Create a new node.
	n := node.Node{
		ID: nodeSigner.Public(),
		P2P: node.P2PInfo{
			ID: p2pSigner1.Public(),
		},
		Consensus: node.ConsensusInfo{
			ID: consensusSigner1.Public(),
		},
		Committee: node.CommitteeInfo{
			Certificate: []byte("this is a certificate"),
		},
	}
	err := s.SetNode(ctx, nil, &n, mustMultiSignNode(t, &n))
	require.NoError(err, "SetNode")

	// Make sure all indices have been created.
	consensusAddress := []byte(tmcrypto.PublicKeyToTendermint(&n.Consensus.ID).Address())

	resNode, err := s.NodeByConsensusAddress(ctx, consensusAddress)
	require.NoError(err, "consensus mapping should be there")
	require.EqualValues(n, *resNode, "returned node should be correct")
	resNode, err = s.NodeByConsensusOrP2PKey(ctx, consensusSigner1.Public())
	require.NoError(err, "consensus mapping should be there")
	require.EqualValues(n, *resNode, "returned node should be correct")
	resNode, err = s.NodeByConsensusOrP2PKey(ctx, p2pSigner1.Public())
	require.NoError(err, "P2P mapping should be there")
	require.EqualValues(n, *resNode, "returned node should be correct")
	resNode, err = s.NodeByCertificate(ctx, n.Committee.Certificate)
	require.NoError(err, "certificate mapping should be there")
	require.EqualValues(n, *resNode, "returned node should be correct")

	// Update the node with the same descriptor -- nothing should change.
	err = s.SetNode(ctx, nil, &n, mustMultiSignNode(t, &n))
	require.NoError(err, "SetNode")

	resNode, err = s.NodeByConsensusAddress(ctx, consensusAddress)
	require.NoError(err, "consensus mapping should be there")
	require.EqualValues(n, *resNode, "returned node should be correct")
	resNode, err = s.NodeByConsensusOrP2PKey(ctx, consensusSigner1.Public())
	require.NoError(err, "consensus mapping should be there")
	require.EqualValues(n, *resNode, "returned node should be correct")
	resNode, err = s.NodeByConsensusOrP2PKey(ctx, p2pSigner1.Public())
	require.NoError(err, "P2P mapping should be there")
	require.EqualValues(n, *resNode, "returned node should be correct")
	resNode, err = s.NodeByCertificate(ctx, n.Committee.Certificate)
	require.NoError(err, "certificate mapping should be there")
	require.EqualValues(n, *resNode, "returned node should be correct")

	// Change the node's consensus/p2p/tls keys and check that indices have been updated.
	newNode := n
	newNode.P2P.ID = p2pSigner2.Public()
	newNode.Consensus.ID = consensusSigner2.Public()
	newNode.Committee.Certificate = []byte("this is another certificate")
	err = s.SetNode(ctx, &n, &newNode, mustMultiSignNode(t, &newNode))
	require.NoError(err, "SetNode")

	newConsensusAddress := []byte(tmcrypto.PublicKeyToTendermint(&newNode.Consensus.ID).Address())

	_, err = s.NodeByConsensusAddress(ctx, consensusAddress)
	require.Error(err, "old consensus mapping should be gone")
	require.Equal(registry.ErrNoSuchNode, err, "old consensus mapping should be gone")
	_, err = s.NodeByConsensusOrP2PKey(ctx, consensusSigner1.Public())
	require.Error(err, "old consensus mapping should be gone")
	require.Equal(registry.ErrNoSuchNode, err, "old consensus mapping should be gone")
	_, err = s.NodeByConsensusOrP2PKey(ctx, p2pSigner1.Public())
	require.Error(err, "old P2P mapping should be gone")
	require.Equal(registry.ErrNoSuchNode, err, "old P2P mapping should be gone")
	_, err = s.NodeByCertificate(ctx, n.Committee.Certificate)
	require.Error(err, "old certificate mapping should be gone")
	require.Equal(registry.ErrNoSuchNode, err, "old certificate mapping should be gone")

	resNode, err = s.NodeByConsensusAddress(ctx, newConsensusAddress)
	require.NoError(err, "new consensus mapping should be there")
	require.EqualValues(newNode, *resNode, "returned node should be correct")
	resNode, err = s.NodeByConsensusOrP2PKey(ctx, consensusSigner2.Public())
	require.NoError(err, "new consensus mapping should be there")
	require.EqualValues(newNode, *resNode, "returned node should be correct")
	resNode, err = s.NodeByConsensusOrP2PKey(ctx, p2pSigner2.Public())
	require.NoError(err, "new P2P mapping should be there")
	require.EqualValues(newNode, *resNode, "returned node should be correct")
	resNode, err = s.NodeByCertificate(ctx, newNode.Committee.Certificate)
	require.NoError(err, "new certificate mapping should be there")
	require.EqualValues(newNode, *resNode, "returned node should be correct")

	// Remove a node and make sure all indices are gone.
	err = s.RemoveNode(ctx, &newNode)
	require.NoError(err, "RemoveNode")

	_, err = s.NodeByConsensusAddress(ctx, newConsensusAddress)
	require.Error(err, "consensus mapping should be gone")
	require.Equal(registry.ErrNoSuchNode, err, "consensus mapping should be gone")
	_, err = s.NodeByConsensusOrP2PKey(ctx, consensusSigner2.Public())
	require.Error(err, "consensus mapping should be gone")
	require.Equal(registry.ErrNoSuchNode, err, "consensus mapping should be gone")
	_, err = s.NodeByConsensusOrP2PKey(ctx, p2pSigner2.Public())
	require.Error(err, "P2P mapping should be gone")
	require.Equal(registry.ErrNoSuchNode, err, "P2P mapping should be gone")
	_, err = s.NodeByCertificate(ctx, newNode.Committee.Certificate)
	require.Error(err, "certificate mapping should be gone")
	require.Equal(registry.ErrNoSuchNode, err, "certificate mapping should be gone")
}
