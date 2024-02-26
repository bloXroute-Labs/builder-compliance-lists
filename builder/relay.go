package builder

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/ofac"
	"github.com/flashbots/go-boost-utils/utils"
)

var ErrValidatorNotFound = errors.New("validator not found")

type RemoteRelay struct {
	client http.Client
	config RelayConfig

	localRelay *LocalRelay

	cancellationsEnabled bool

	validatorsLock       sync.RWMutex
	validatorSyncOngoing bool
	lastRequestedSlot    uint64
	validatorSlotMap     map[uint64]ValidatorData
}

func NewRemoteRelay(config RelayConfig, localRelay *LocalRelay, cancellationsEnabled bool) *RemoteRelay {
	r := &RemoteRelay{
		client:               http.Client{Timeout: time.Second},
		localRelay:           localRelay,
		cancellationsEnabled: cancellationsEnabled,
		validatorSyncOngoing: false,
		lastRequestedSlot:    0,
		validatorSlotMap:     make(map[uint64]ValidatorData),
		config:               config,
	}

	err := r.updateValidatorsMap(0, 3)
	if err != nil {
		log.Error("could not connect to remote relay to update validators map, continuing anyway", "err", err)
	}

	if r.config.ComplianceListsEnabled {
		err = r.updateComplianceLists(0, 3)
		if err != nil {
			log.Error("could not connect to remote relay to update compliance lists, continuing anyway", "err", err)
		}
	}

	return r
}

type GetValidatorRelayResponse []struct {
	Slot  uint64 `json:"slot,string"`
	Entry struct {
		Message struct {
			FeeRecipient string `json:"fee_recipient"`
			GasLimit     uint64 `json:"gas_limit,string"`
			Timestamp    uint64 `json:"timestamp,string"`
			Pubkey       string `json:"pubkey"`
		} `json:"message"`
		Signature string `json:"signature"`
	} `json:"entry"`
	ComplianceList string `json:"compliance_list"`
}

type GetComplianceListRelayResponse map[string]ofac.ComplianceList

func (r *RemoteRelay) updateValidatorsMap(currentSlot uint64, retries int) error {
	r.validatorsLock.Lock()
	if r.validatorSyncOngoing {
		r.validatorsLock.Unlock()
		return errors.New("sync is ongoing")
	}
	r.validatorSyncOngoing = true
	r.validatorsLock.Unlock()

	log.Info("requesting validators", "currentSlot", currentSlot)
	newMap, err := r.getSlotValidatorMapFromRelay()
	for err != nil && retries > 0 {
		log.Error("could not get validators map from relay, retrying", "err", err)
		time.Sleep(time.Second)
		newMap, err = r.getSlotValidatorMapFromRelay()
		retries -= 1
	}
	r.validatorsLock.Lock()
	r.validatorSyncOngoing = false
	if err != nil {
		r.validatorsLock.Unlock()
		log.Error("could not get validators map from relay", "err", err)
		return err
	}

	r.validatorSlotMap = newMap
	r.lastRequestedSlot = currentSlot
	r.validatorsLock.Unlock()

	log.Info("Updated validators", "count", len(newMap), "slot", currentSlot)
	return nil
}

func (r *RemoteRelay) updateComplianceLists(currentSlot uint64, retries int) error {
	// determine which compliance lists we need to request by looking at the current validator slot map
	listsToRequest := make(map[string]bool)
	r.validatorsLock.RLock()
	for _, data := range r.validatorSlotMap {
		if data.ComplianceList != "" {
			listsToRequest[data.ComplianceList] = true
		}
	}
	r.validatorsLock.RUnlock()

	if len(listsToRequest) == 0 {
		log.Info("skipping compliance list update, no validator requested a compliance list this epoch", "currentSlot", currentSlot)
		return nil
	}

	log.Info("requesting compliance lists", "currentSlot", currentSlot)
	newMap, err := r.getComplianceListsMapFromRelay(listsToRequest)
	for err != nil && retries > 0 {
		log.Error("could not get compliance lists from relay, retrying", "err", err)
		time.Sleep(time.Second)
		newMap, err = r.getComplianceListsMapFromRelay(listsToRequest)
		retries -= 1
	}
	if err != nil {
		log.Error("could not get compliance lists from relay", "err", err)
		return err
	}

	ofac.UpdateComplianceLists(newMap)

	log.Info("Updated compliance lists", "count", len(newMap), "slot", currentSlot)
	return nil
}

func (r *RemoteRelay) GetValidatorForSlot(nextSlot uint64) (ValidatorData, error) {
	// next slot is expected to be the actual chain's next slot, not something requested by the user!
	// if not sanitized it will force resync of validator data and possibly is a DoS vector

	r.validatorsLock.RLock()
	if r.lastRequestedSlot == 0 || nextSlot/32 > r.lastRequestedSlot/32 {
		// Every epoch request validators map and update compliance lists
		go func() {
			err := r.updateValidatorsMap(nextSlot, 1)
			if err != nil {
				log.Error("could not update validators map", "err", err)
			}

			if r.config.ComplianceListsEnabled {
				err = r.updateComplianceLists(nextSlot, 1)
				if err != nil {
					log.Error("could not update compliance lists", "err", err)
				}
			}
		}()
	}

	vd, found := r.validatorSlotMap[nextSlot]
	r.validatorsLock.RUnlock()

	if r.localRelay != nil {
		localValidator, err := r.localRelay.GetValidatorForSlot(nextSlot)
		if err == nil {
			log.Info("Validator registration overwritten by local data", "slot", nextSlot, "validator", localValidator)
			return localValidator, nil
		}
	}

	if found {
		return vd, nil
	}

	return ValidatorData{}, ErrValidatorNotFound
}

func (r *RemoteRelay) Start() error {
	return nil
}

func (r *RemoteRelay) Stop() {}

func (r *RemoteRelay) SubmitBlock(msg *builderSpec.VersionedSubmitBlockRequest, _ ValidatorData) error {
	log.Info("submitting block to remote relay", "endpoint", r.config.Endpoint)
	endpoint := r.config.Endpoint + "/relay/v1/builder/blocks"
	if r.cancellationsEnabled {
		endpoint = endpoint + "?cancellations=true"
	}

	var code int
	var err error
	if r.config.SszEnabled {
		var bodyBytes []byte
		switch msg.Version {
		case spec.DataVersionBellatrix:
			bodyBytes, err = msg.Bellatrix.MarshalSSZ()
		case spec.DataVersionCapella:
			bodyBytes, err = msg.Capella.MarshalSSZ()
		case spec.DataVersionDeneb:
			bodyBytes, err = msg.Deneb.MarshalSSZ()
		default:
			return fmt.Errorf("unknown data version %d", msg.Version)
		}
		if err != nil {
			return fmt.Errorf("error marshaling ssz: %w", err)
		}
		log.Debug("submitting block to remote relay", "endpoint", r.config.Endpoint)
		code, err = SendSSZRequest(context.TODO(), *http.DefaultClient, http.MethodPost, endpoint, bodyBytes, r.config.GzipEnabled)
	} else {
		switch msg.Version {
		case spec.DataVersionBellatrix:
			code, err = SendHTTPRequest(context.TODO(), *http.DefaultClient, http.MethodPost, endpoint, msg.Bellatrix, nil, false)
		case spec.DataVersionCapella:
			code, err = SendHTTPRequest(context.TODO(), *http.DefaultClient, http.MethodPost, endpoint, msg.Capella, nil, false)
		case spec.DataVersionDeneb:
			code, err = SendHTTPRequest(context.TODO(), *http.DefaultClient, http.MethodPost, endpoint, msg.Deneb, nil, false)
		default:
			return fmt.Errorf("unknown data version %d", msg.Version)
		}
	}

	if err != nil {
		return fmt.Errorf("error sending http request to relay %s. err: %w", r.config.Endpoint, err)
	}
	if code > 299 {
		return fmt.Errorf("non-ok response code %d from relay %s", code, r.config.Endpoint)
	}

	return nil
}

func (r *RemoteRelay) getSlotValidatorMapFromRelay() (map[uint64]ValidatorData, error) {
	var dst GetValidatorRelayResponse
	code, err := SendHTTPRequest(context.TODO(), *http.DefaultClient, http.MethodGet, r.config.Endpoint+"/relay/v1/builder/validators", nil, &dst, false)
	if err != nil {
		return nil, err
	}

	if code > 299 {
		return nil, fmt.Errorf("non-ok response code %d from relay", code)
	}

	res := make(map[uint64]ValidatorData)
	for _, data := range dst {
		feeRecipient, err := utils.HexToAddress(data.Entry.Message.FeeRecipient)
		if err != nil {
			log.Error("Ill-formatted fee_recipient from relay", "data", data)
			continue
		}

		pubkeyHex := PubkeyHex(strings.ToLower(data.Entry.Message.Pubkey))

		res[data.Slot] = ValidatorData{
			Pubkey:         pubkeyHex,
			FeeRecipient:   feeRecipient,
			GasLimit:       data.Entry.Message.GasLimit,
			ComplianceList: data.ComplianceList,
		}
	}

	return res, nil
}

func (r *RemoteRelay) getComplianceListsMapFromRelay(listsToRequest map[string]bool) (GetComplianceListRelayResponse, error) {
	url := fmt.Sprintf("%v/blxr/compliance_lists?", r.config.Endpoint)

	// add a query parameter for each list we need to request
	for key := range listsToRequest {
		if strings.Contains(url, "list=") {
			url += "&"
		}
		url += fmt.Sprintf("list=%s", key)
	}

	var dst GetComplianceListRelayResponse
	code, err := SendHTTPRequest(context.TODO(), *http.DefaultClient, http.MethodGet, url, nil, &dst, true)
	if err != nil {
		return nil, err
	}

	if code > 299 {
		return nil, fmt.Errorf("non-ok response code %d from relay", code)
	}

	return dst, nil
}

func (r *RemoteRelay) Config() RelayConfig {
	return r.config
}
