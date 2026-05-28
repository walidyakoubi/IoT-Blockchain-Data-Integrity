// iot_contract.go — Hyperledger Fabric chaincode for IoT Data Integrity
// =====================================================================
// Version 1.2 — adds per-type access policies on top of v1.1 per-device.
//
// Compatibility:
//   v1.0 functions (StoreHash, VerifyHash, GetRecord)            unchanged
//   v1.1 functions (RegisterDevice, GetPolicy, UpdatePolicy,
//                   LogAccess, GetAccessLog)                     compatible
//   v1.1 CheckAccess                                             MODIFIED
//       (now consults both per-device and per-type policies;
//        composition rule: AND, least-permissive visibility)
//
// New in v1.2:
//   AccessPolicy now carries a SensorType field
//   PolicyByType  — new asset, one per sensor class
//   RegisterTypePolicy / GetTypePolicy / UpdateTypePolicy
//
// Author: PFE — Telecommunication Systems, USTHB

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ─────────────────────────────────────────────────────────────────────────────
// Asset types
// ─────────────────────────────────────────────────────────────────────────────

// IntegrityRecord anchors the SHA-256 hash of an off-chain reading.
// Schema preserved from v1.0 for backward compatibility.
type IntegrityRecord struct {
	RecordID  string `json:"record_id"`
	DeviceID  string `json:"device_id"`
	Hash      string `json:"hash"`
	Timestamp int64  `json:"timestamp"`
}

// AccessPolicy is the per-device authorisation policy.
// v1.2 adds SensorType so CheckAccess can look up the type-level policy.
type AccessPolicy struct {
	DeviceID   string            `json:"device_id"`
	OwnerOrg   string            `json:"owner_org"`
	SensorType string            `json:"sensor_type"` // "temp"|"hum"|"press"|"" (legacy)
	Readers    []string          `json:"readers"`
	Visibility map[string]string `json:"visibility"`
}

// PolicyByType is the per-sensor-type authorisation policy. NEW in v1.2.
// Stored under key "policy_type_<sensor_type>".
type PolicyByType struct {
	SensorType string            `json:"sensor_type"`
	OwnerOrg   string            `json:"owner_org"`
	Readers    []string          `json:"readers"`
	Visibility map[string]string `json:"visibility"`
}

// AccessLogEntry records one authorisation decision.
// Stored under composite key ("access", device_id, timestamp, consumer).
type AccessLogEntry struct {
	LogID     string `json:"log_id"`
	DeviceID  string `json:"device_id"`
	Consumer  string `json:"consumer"`
	Role      string `json:"role"`
	Timestamp int64  `json:"timestamp"`
	Granted   bool   `json:"granted"`
	Reason    string `json:"reason"`
}

// SmartContract is the chaincode entry point.
type SmartContract struct {
	contractapi.Contract
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// stringIn — substring-free containment check.
func stringIn(needle string, haystack []string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// visRank — total order over visibility levels.
// Higher rank means more permissive. "denied" is the bottom.
var visRank = map[string]int{
	"denied":     0,
	"hash-only":  1,
	"aggregated": 2,
	"full":       3,
}

// minVisibility returns the less permissive of two visibility levels.
// Used by CheckAccess to compose per-device and per-type grants.
func minVisibility(a, b string) string {
	ra, ok := visRank[a]
	if !ok {
		return "denied"
	}
	rb, ok := visRank[b]
	if !ok {
		return "denied"
	}
	if ra <= rb {
		return a
	}
	return b
}

// validSensorType — keep synced with udp-client.c's choose_profile().
func validSensorType(t string) bool {
	switch t {
	case "temp", "hum", "press", "":
		return true
	default:
		return false
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// v1.0 — Integrity anchoring (unchanged)
// ─────────────────────────────────────────────────────────────────────────────

// StoreHash anchors a SHA-256 hash of an off-chain reading.
func (s *SmartContract) StoreHash(
	ctx contractapi.TransactionContextInterface,
	recordID, deviceID, hash string, timestamp int64,
) error {
	if recordID == "" || hash == "" {
		return fmt.Errorf("record_id and hash are required")
	}
	rec := IntegrityRecord{
		RecordID:  recordID,
		DeviceID:  deviceID,
		Hash:      hash,
		Timestamp: timestamp,
	}
	bytes, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(recordID, bytes)
}

// VerifyHash checks whether a candidate hash matches the on-chain value.
func (s *SmartContract) VerifyHash(
	ctx contractapi.TransactionContextInterface,
	recordID, candidateHash string,
) (bool, error) {
	bytes, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return false, err
	}
	if bytes == nil {
		return false, nil
	}
	var rec IntegrityRecord
	if err := json.Unmarshal(bytes, &rec); err != nil {
		return false, err
	}
	return rec.Hash == candidateHash, nil
}

// GetRecord returns the integrity record for a given recordID.
func (s *SmartContract) GetRecord(
	ctx contractapi.TransactionContextInterface, recordID string,
) (*IntegrityRecord, error) {
	bytes, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return nil, err
	}
	if bytes == nil {
		return nil, fmt.Errorf("record not found: %s", recordID)
	}
	var rec IntegrityRecord
	if err := json.Unmarshal(bytes, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// v1.1 — Per-device access policy (AccessPolicy extended with SensorType)
// ─────────────────────────────────────────────────────────────────────────────

// RegisterDevice provisions a device with its access policy.
// v1.2 adds the sensorType parameter (use "" for backward compatibility).
func (s *SmartContract) RegisterDevice(
	ctx contractapi.TransactionContextInterface,
	deviceID, ownerOrg, sensorType, readersJSON, visibilityJSON string,
) error {
	if deviceID == "" {
		return fmt.Errorf("device_id is required")
	}
	if !validSensorType(sensorType) {
		return fmt.Errorf("unsupported sensor_type: %s", sensorType)
	}

	var readers []string
	if err := json.Unmarshal([]byte(readersJSON), &readers); err != nil {
		return fmt.Errorf("invalid readers JSON: %v", err)
	}
	var visibility map[string]string
	if err := json.Unmarshal([]byte(visibilityJSON), &visibility); err != nil {
		return fmt.Errorf("invalid visibility JSON: %v", err)
	}

	policy := AccessPolicy{
		DeviceID:   deviceID,
		OwnerOrg:   ownerOrg,
		SensorType: sensorType,
		Readers:    readers,
		Visibility: visibility,
	}
	bytes, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState("policy_"+deviceID, bytes)
}

// GetPolicy returns the per-device policy.
func (s *SmartContract) GetPolicy(
	ctx contractapi.TransactionContextInterface, deviceID string,
) (*AccessPolicy, error) {
	bytes, err := ctx.GetStub().GetState("policy_" + deviceID)
	if err != nil {
		return nil, err
	}
	if bytes == nil {
		return nil, fmt.Errorf("no policy for device %s", deviceID)
	}
	var p AccessPolicy
	if err := json.Unmarshal(bytes, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdatePolicy replaces readers and visibility of an existing device policy.
// The DeviceID, OwnerOrg, and SensorType fields are immutable.
func (s *SmartContract) UpdatePolicy(
	ctx contractapi.TransactionContextInterface,
	deviceID, readersJSON, visibilityJSON string,
) error {
	key := "policy_" + deviceID
	bytes, err := ctx.GetStub().GetState(key)
	if err != nil || bytes == nil {
		return fmt.Errorf("no policy for device %s (use RegisterDevice first)", deviceID)
	}
	var p AccessPolicy
	if err := json.Unmarshal(bytes, &p); err != nil {
		return err
	}
	var readers []string
	if err := json.Unmarshal([]byte(readersJSON), &readers); err != nil {
		return fmt.Errorf("invalid readers JSON: %v", err)
	}
	var visibility map[string]string
	if err := json.Unmarshal([]byte(visibilityJSON), &visibility); err != nil {
		return fmt.Errorf("invalid visibility JSON: %v", err)
	}
	p.Readers = readers
	p.Visibility = visibility
	out, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, out)
}

// ─────────────────────────────────────────────────────────────────────────────
// v1.2 NEW — Per-type access policy
// ─────────────────────────────────────────────────────────────────────────────

// RegisterTypePolicy creates a policy that applies to every device of the
// given sensor type. Fails if a policy already exists for that type.
func (s *SmartContract) RegisterTypePolicy(
	ctx contractapi.TransactionContextInterface,
	sensorType, ownerOrg, readersJSON, visibilityJSON string,
) error {
	if !validSensorType(sensorType) || sensorType == "" {
		return fmt.Errorf("unsupported sensor_type: %s", sensorType)
	}
	key := "policy_type_" + sensorType
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("type policy already exists for %s (use UpdateTypePolicy)",
			sensorType)
	}
	var readers []string
	if err := json.Unmarshal([]byte(readersJSON), &readers); err != nil {
		return fmt.Errorf("invalid readers JSON: %v", err)
	}
	var visibility map[string]string
	if err := json.Unmarshal([]byte(visibilityJSON), &visibility); err != nil {
		return fmt.Errorf("invalid visibility JSON: %v", err)
	}
	p := PolicyByType{
		SensorType: sensorType,
		OwnerOrg:   ownerOrg,
		Readers:    readers,
		Visibility: visibility,
	}
	bytes, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, bytes)
}

// GetTypePolicy returns the policy for a sensor class. Returns nil if absent.
func (s *SmartContract) GetTypePolicy(
	ctx contractapi.TransactionContextInterface, sensorType string,
) (*PolicyByType, error) {
	bytes, err := ctx.GetStub().GetState("policy_type_" + sensorType)
	if err != nil {
		return nil, err
	}
	if bytes == nil {
		return nil, nil // not an error; type policies are optional
	}
	var p PolicyByType
	if err := json.Unmarshal(bytes, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdateTypePolicy replaces readers and visibility of an existing type policy.
// SensorType and OwnerOrg are immutable.
func (s *SmartContract) UpdateTypePolicy(
	ctx contractapi.TransactionContextInterface,
	sensorType, readersJSON, visibilityJSON string,
) error {
	key := "policy_type_" + sensorType
	bytes, err := ctx.GetStub().GetState(key)
	if err != nil || bytes == nil {
		return fmt.Errorf("no type policy for %s (use RegisterTypePolicy first)",
			sensorType)
	}
	var p PolicyByType
	if err := json.Unmarshal(bytes, &p); err != nil {
		return err
	}
	var readers []string
	if err := json.Unmarshal([]byte(readersJSON), &readers); err != nil {
		return fmt.Errorf("invalid readers JSON: %v", err)
	}
	var visibility map[string]string
	if err := json.Unmarshal([]byte(visibilityJSON), &visibility); err != nil {
		return fmt.Errorf("invalid visibility JSON: %v", err)
	}
	p.Readers = readers
	p.Visibility = visibility
	out, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, out)
}

// ─────────────────────────────────────────────────────────────────────────────
// v1.2 — CheckAccess with two-layer fail-closed composition
// ─────────────────────────────────────────────────────────────────────────────

// CheckAccess returns the effective visibility level for `role` on `deviceID`.
// Composition rule: AND, least-permissive. A reader is granted access if AND
// ONLY IF both the per-device policy and (if present) the per-type policy
// list the role as a reader. The returned visibility level is the LESS
// permissive of the two grants.
//
// Returns the string "denied" for any failure mode — missing policy, role
// not in readers, ledger error, JSON parse error. The single failure-mode
// design avoids leaking the structural reason for denial (no probing oracle).
func (s *SmartContract) CheckAccess(
	ctx contractapi.TransactionContextInterface,
	deviceID, role string,
) (string, error) {
	// 1) Per-device policy is mandatory.
	devBytes, err := ctx.GetStub().GetState("policy_" + deviceID)
	if err != nil || devBytes == nil {
		return "denied", nil
	}
	var devPolicy AccessPolicy
	if err := json.Unmarshal(devBytes, &devPolicy); err != nil {
		return "denied", nil
	}

	devVis, devOk := devPolicy.Visibility[role]
	if !devOk || !stringIn(role, devPolicy.Readers) {
		return "denied", nil
	}

	// 2) Per-type policy is optional but, if present, must also grant.
	if devPolicy.SensorType == "" {
		// Legacy device (registered before v1.2): no type known → device-only.
		return devVis, nil
	}
	typeBytes, err := ctx.GetStub().GetState("policy_type_" + devPolicy.SensorType)
	if err != nil {
		return "denied", nil
	}
	if typeBytes == nil {
		// No type policy exists → device-level grant stands.
		return devVis, nil
	}
	var typePolicy PolicyByType
	if err := json.Unmarshal(typeBytes, &typePolicy); err != nil {
		return "denied", nil
	}
	typeVis, typeOk := typePolicy.Visibility[role]
	if !typeOk || !stringIn(role, typePolicy.Readers) {
		return "denied", nil
	}

	// 3) Both grant — return the LEAST permissive visibility.
	return minVisibility(devVis, typeVis), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit log (v1.1, unchanged in v1.2)
// ─────────────────────────────────────────────────────────────────────────────

// LogAccess appends one authorisation decision to the on-chain audit log.
func (s *SmartContract) LogAccess(
	ctx contractapi.TransactionContextInterface,
	deviceID, consumer, role string, timestamp int64,
	granted bool, reason string,
) error {
	tsStr := strconv.FormatInt(timestamp, 10)
	key, err := ctx.GetStub().CreateCompositeKey(
		"access", []string{deviceID, tsStr, consumer},
	)
	if err != nil {
		return err
	}
	entry := AccessLogEntry{
		LogID:     key,
		DeviceID:  deviceID,
		Consumer:  consumer,
		Role:      role,
		Timestamp: timestamp,
		Granted:   granted,
		Reason:    reason,
	}
	bytes, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, bytes)
}

// GetAccessLog returns all audit entries for a given device, ordered by
// composite-key iteration order (effectively chronological).
func (s *SmartContract) GetAccessLog(
	ctx contractapi.TransactionContextInterface, deviceID string,
) ([]*AccessLogEntry, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(
		"access", []string{deviceID},
	)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var entries []*AccessLogEntry
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var entry AccessLogEntry
		if err := json.Unmarshal(kv.Value, &entry); err != nil {
			continue // skip malformed entries rather than failing the whole query
		}
		entries = append(entries, &entry)
	}
	return entries, nil
}

// CurrentTimestampMs is a small helper exposed for clients that want the
// chain's notion of "now" rather than their local clock. Not used internally.
func (s *SmartContract) CurrentTimestampMs(
	_ contractapi.TransactionContextInterface,
) (int64, error) {
	return time.Now().UnixMilli(), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		panic(fmt.Sprintf("error creating chaincode: %v", err))
	}

	ccid := os.Getenv("CHAINCODE_ID")
	address := os.Getenv("CHAINCODE_SERVER_ADDRESS")

	if address != "" {
		if ccid == "" {
			panic("CHAINCODE_ID must be set for CCaaS mode")
		}

		server := &shim.ChaincodeServer{
			CCID:    ccid,
			Address: address,
			CC:      chaincode,
			TLSProps: shim.TLSProperties{
				Disabled: true,
			},
		}

		if err := server.Start(); err != nil {
			panic(fmt.Sprintf("error starting chaincode server: %v", err))
		}
		return
	}

	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("error starting chaincode: %v", err))
	}
}
