package joinserver

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/brocaar/lorawan"
	"github.com/pkg/errors"

	"github.com/brocaar/lorawan/backend"
)

const (
	MakeCredentialBegin  = 0x0
	MakeCredentialFinish = 0x1
	GetAssertionBegin    = 0x2
	GetAssertionFinish   = 0x3
)

var joinTasks = []func(*context) error{
	setJoinContext,
	validateMIC,
	setJoinNonce,
	setSessionKeys,
	createJoinAnsPayload,
}

var fidoJoinTasks = []func(*context) error{
	doFidoStuff,
	validateMIC,
	setJoinNonce,
	setSessionKeys,
	createJoinAnsPayload,
}

func handleJoinRequestWrapper(joinReqPL backend.JoinReqPayload, dk DeviceKeys, asKEKLabel string, asKEK []byte, nsKEKLabel string, nsKEK []byte) backend.JoinAnsPayload {
	basePayload := backend.BasePayload{
		ProtocolVersion: backend.ProtocolVersion1_0,
		SenderID:        joinReqPL.ReceiverID,
		ReceiverID:      joinReqPL.SenderID,
		TransactionID:   joinReqPL.TransactionID,
		MessageType:     backend.JoinAns,
	}

	jaPL, err := handleJoinRequest(joinReqPL, dk, asKEKLabel, asKEK, nsKEKLabel, nsKEK)
	if err != nil {
		var resCode backend.ResultCode

		switch errors.Cause(err) {
		case ErrInvalidMIC:
			resCode = backend.MICFailed
		default:
			resCode = backend.Other
		}

		jaPL = backend.JoinAnsPayload{
			BasePayloadResult: backend.BasePayloadResult{
				BasePayload: basePayload,
				Result: backend.Result{
					ResultCode:  resCode,
					Description: err.Error(),
				},
			},
		}
	}

	jaPL.BasePayload = basePayload
	return jaPL
}

func handleJoinRequest(joinReqPL backend.JoinReqPayload, dk DeviceKeys, asKEKLabel string, asKEK []byte, nsKEKLabel string, nsKEK []byte) (backend.JoinAnsPayload, error) {
	ctx := context{
		joinReqPayload: joinReqPL,
		deviceKeys:     dk,
		asKEKLabel:     asKEKLabel,
		asKEK:          asKEK,
		nsKEKLabel:     nsKEKLabel,
		nsKEK:          nsKEK,
	}

	// first step of joinTasks
	err := setJoinContext(&ctx)
	if err != nil {
		return ctx.joinAnsPayload, err
	}

	if len(ctx.fidoData.Bytes) > 0x0 {
		log.Println("Executing fido jointasks")
		for _, f := range fidoJoinTasks {
			if err := f(&ctx); err != nil {
				return ctx.joinAnsPayload, err
			}
		}
	} else {
		log.Println("Executing normal LoRaWAN jointasks")
		for _, f := range joinTasks[1:] {
			if err := f(&ctx); err != nil {
				return ctx.joinAnsPayload, err
			}
		}
	}

	/*
		for _, f := range joinTasks {
			if err := f(&ctx); err != nil {
				return ctx.joinAnsPayload, err
			}
		}
	*/

	return ctx.joinAnsPayload, nil
}

func setJoinContext(ctx *context) error {
	if err := ctx.phyPayload.UnmarshalBinary(ctx.joinReqPayload.PHYPayload[:]); err != nil {
		return errors.Wrap(err, "unmarshal phypayload error")
	}

	if err := ctx.netID.UnmarshalText([]byte(ctx.joinReqPayload.SenderID)); err != nil {
		return errors.Wrap(err, "unmarshal netid error")
	}

	if err := ctx.joinEUI.UnmarshalText([]byte(ctx.joinReqPayload.ReceiverID)); err != nil {
		return errors.Wrap(err, "unmarshal joineui error")
	}

	ctx.devEUI = ctx.joinReqPayload.DevEUI
	ctx.joinType = lorawan.JoinRequestType

	switch v := ctx.phyPayload.MACPayload.(type) {
	case *lorawan.JoinRequestPayload:
		ctx.devNonce = v.DevNonce
		ctx.fidoData = v.FidoData
	default:
		return fmt.Errorf("expected *lorawan.JoinRequestPayload, got %T", ctx.phyPayload.MACPayload)
	}

	return nil
}

func validateMIC(ctx *context) error {
	ok, err := ctx.phyPayload.ValidateUplinkJoinMIC(ctx.deviceKeys.NwkKey)
	if err != nil {
		return errors.Wrap(err, "validate mic error")
	}
	if !ok {
		return ErrInvalidMIC
	}
	return nil
}

func setJoinNonce(ctx *context) error {
	if ctx.deviceKeys.JoinNonce > (1<<24)-1 {
		return errors.New("join-nonce overflow")
	}
	ctx.joinNonce = lorawan.JoinNonce(ctx.deviceKeys.JoinNonce)
	return nil
}

const Url = "http://localhost:8005/fidodata/"

type FidoResponse struct {
	FidoData  []byte `json:"fidoData"`
	PublicKey []byte `json:"publicKey,omitempty"`
}

var timer time.Time

func doFidoStuff(ctx *context) error {
	if len(ctx.fidoData.Bytes) == 0x0 {
		return nil
	}

	var req_type = ctx.fidoData.Bytes[0x0]
	if req_type == GetAssertionFinish {
		elapsed := time.Since(timer)
		fmt.Println("Device communication took: ", elapsed)
	}
	data := url.Values{}
	data.Set("fidoData", string(ctx.fidoData.Bytes))
	enc := data.Encode()

	req_url := Url + ctx.devEUI.String()

	req, err := http.NewRequest("POST", req_url, strings.NewReader(enc))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))
	if err != nil {
		return errors.Wrap(err, "Fido http request fail")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Fido http request fail")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var fidoResp FidoResponse
	err = json.Unmarshal(body, &fidoResp)
	if err != nil {
		return err
	}

	// todo: check how much space can be saved when leaving out the req_type here
	// makes resp bigger due to encryption padding
	// client could know state so not needed
	if len(fidoResp.FidoData) > 0xff {
		log.Println("ERROR: fido data > 0xff")
	}
	var data_len uint8 = uint8(len(fidoResp.FidoData))

	fidoResp.FidoData = append([]byte{data_len}, fidoResp.FidoData...)

	// assure FidoData is a multiple of 16 (for MIC calculation)
	if len(fidoResp.FidoData)%16 != 0 {
		fidoResp.FidoData = append(fidoResp.FidoData, make([]byte, 0x10-len(fidoResp.FidoData)%16)...)
	}

	// device sent public key. Use that one instead of pub key returned from FIDO2 server
	if len(ctx.fidoData.Bytes) == 64+1 && req_type == GetAssertionBegin {
		log.Println("Using public key sent by device")
		fidoResp.PublicKey = ctx.fidoData.Bytes[1:]
	} else {
		log.Println("Using public key sent by fido2 server")
	}

	ctx.fidoData.Bytes = fidoResp.FidoData

	// no else branch because if assertion is wrong http request would return != 200
	if req_type == GetAssertionBegin {
		// log.Println("Fido pub key: ", fidoResp.PublicKey, len(fidoResp.PublicKey))

		if len(fidoResp.PublicKey) < 0x40 {
			return errors.New("no / invalid fido public key returned")
		}

		priv_js := []byte{0xf2, 0x93, 0x93, 0x97, 0x1f, 0x62, 0x2c, 0x8b, 0x1e, 0xb9, 0xec, 0x84, 0x6c, 0x8c, 0x6a, 0xe6, 0xa9, 0x5a, 0xe1, 0xc3, 0xbc, 0x76, 0x27, 0x65, 0xee, 0x7d, 0x1c, 0x18, 0xac, 0x85, 0x55, 0x61}
		//_ = priv_js

		// elliptic curve diffie hellman
		p256 := elliptic.P256()

		var pub_x big.Int
		pub_x.SetBytes(fidoResp.PublicKey[:32])
		var pub_y big.Int
		pub_y.SetBytes(fidoResp.PublicKey[32:])

		s_x, _ := p256.ScalarMult(&pub_x, &pub_y, priv_js)

		log.Println("Secret: ", hex.EncodeToString(s_x.Bytes()))

		new_keys := sha256.Sum256(s_x.Bytes())

		copy(ctx.deviceKeys.AppKey[:], new_keys[:])
		copy(ctx.deviceKeys.NwkKey[:], new_keys[16:])

		ctx.joinAnsPayload.KeyUpdate.Set = true
		ctx.joinAnsPayload.KeyUpdate.DevEUI = ctx.devEUI
		ctx.joinAnsPayload.KeyUpdate.NwkKey = ctx.deviceKeys.NwkKey
		ctx.joinAnsPayload.KeyUpdate.AppKey = ctx.deviceKeys.AppKey
	}

	log.Println("AppKey: ", hex.EncodeToString(ctx.deviceKeys.AppKey[:]))
	log.Println("NwkKey: ", hex.EncodeToString(ctx.deviceKeys.NwkKey[:]))

	if req_type == GetAssertionBegin {
		timer = time.Now()
	}

	return nil
}

func setSessionKeys(ctx *context) error {
	var err error

	ctx.fNwkSIntKey, err = getFNwkSIntKey(ctx.joinReqPayload.DLSettings.OptNeg, ctx.deviceKeys.NwkKey, ctx.netID, ctx.joinEUI, ctx.joinNonce, ctx.devNonce)
	if err != nil {
		return errors.Wrap(err, "get FNwkSIntKey error")
	}

	if ctx.joinReqPayload.DLSettings.OptNeg {
		ctx.appSKey, err = getAppSKey(ctx.joinReqPayload.DLSettings.OptNeg, ctx.deviceKeys.AppKey, ctx.netID, ctx.joinEUI, ctx.joinNonce, ctx.devNonce)
		if err != nil {
			return errors.Wrap(err, "get AppSKey error")
		}
	} else {
		ctx.appSKey, err = getAppSKey(ctx.joinReqPayload.DLSettings.OptNeg, ctx.deviceKeys.NwkKey, ctx.netID, ctx.joinEUI, ctx.joinNonce, ctx.devNonce)
		if err != nil {
			return errors.Wrap(err, "get AppSKey error")
		}
	}

	ctx.sNwkSIntKey, err = getSNwkSIntKey(ctx.joinReqPayload.DLSettings.OptNeg, ctx.deviceKeys.NwkKey, ctx.netID, ctx.joinEUI, ctx.joinNonce, ctx.devNonce)
	if err != nil {
		return errors.Wrap(err, "get SNwkSIntKey error")
	}

	ctx.nwkSEncKey, err = getNwkSEncKey(ctx.joinReqPayload.DLSettings.OptNeg, ctx.deviceKeys.NwkKey, ctx.netID, ctx.joinEUI, ctx.joinNonce, ctx.devNonce)
	if err != nil {
		return errors.Wrap(err, "get NwkSEncKey error")
	}

	return nil
}

func createJoinAnsPayload(ctx *context) error {
	var cFList *lorawan.CFList
	if len(ctx.joinReqPayload.CFList[:]) != 0 {
		log.Println("Setting cFList")
		cFList = new(lorawan.CFList)
		if err := cFList.UnmarshalBinary(ctx.joinReqPayload.CFList[:]); err != nil {
			return errors.Wrap(err, "unmarshal cflist error")
		}
	}

	phy := lorawan.PHYPayload{
		MHDR: lorawan.MHDR{
			MType: lorawan.JoinAccept,
			Major: lorawan.LoRaWANR1,
		},
		MACPayload: &lorawan.JoinAcceptPayload{
			JoinNonce:  ctx.joinNonce,
			HomeNetID:  ctx.netID,
			DevAddr:    ctx.joinReqPayload.DevAddr,
			DLSettings: ctx.joinReqPayload.DLSettings,
			RXDelay:    uint8(ctx.joinReqPayload.RxDelay),
			CFList:     cFList,
			FidoData:   ctx.fidoData,
		},
	}

	if ctx.joinReqPayload.DLSettings.OptNeg {
		jsIntKey, err := getJSIntKey(ctx.deviceKeys.NwkKey, ctx.devEUI)
		if err != nil {
			return err
		}
		if err := phy.SetDownlinkJoinMIC(ctx.joinType, ctx.joinEUI, ctx.devNonce, jsIntKey); err != nil {
			return err
		}
	} else {
		if err := phy.SetDownlinkJoinMIC(ctx.joinType, ctx.joinEUI, ctx.devNonce, ctx.deviceKeys.NwkKey); err != nil {
			return err
		}
	}

	if err := phy.EncryptJoinAcceptPayload(ctx.deviceKeys.NwkKey); err != nil {
		return err
	}

	b, err := phy.MarshalBinary()
	if err != nil {
		return err
	}

	if ctx.joinAnsPayload.KeyUpdate.Set {
		ctx.joinAnsPayload = backend.JoinAnsPayload{
			BasePayloadResult: backend.BasePayloadResult{
				Result: backend.Result{
					ResultCode: backend.Success,
				},
			},
			PHYPayload: backend.HEXBytes(b),
			KeyUpdate:  ctx.joinAnsPayload.KeyUpdate,
			// TODO add Lifetime?
		}

	} else {
		ctx.joinAnsPayload = backend.JoinAnsPayload{
			BasePayloadResult: backend.BasePayloadResult{
				Result: backend.Result{
					ResultCode: backend.Success,
				},
			},
			PHYPayload: backend.HEXBytes(b),
			// TODO add Lifetime?
		}
	}

	ctx.joinAnsPayload.AppSKey, err = backend.NewKeyEnvelope(ctx.asKEKLabel, ctx.asKEK, ctx.appSKey)
	if err != nil {
		return err
	}

	if ctx.joinReqPayload.DLSettings.OptNeg {
		// LoRaWAN 1.1+
		ctx.joinAnsPayload.FNwkSIntKey, err = backend.NewKeyEnvelope(ctx.nsKEKLabel, ctx.nsKEK, ctx.fNwkSIntKey)
		if err != nil {
			return err
		}
		ctx.joinAnsPayload.SNwkSIntKey, err = backend.NewKeyEnvelope(ctx.nsKEKLabel, ctx.nsKEK, ctx.sNwkSIntKey)
		if err != nil {
			return err
		}
		ctx.joinAnsPayload.NwkSEncKey, err = backend.NewKeyEnvelope(ctx.nsKEKLabel, ctx.nsKEK, ctx.nwkSEncKey)
		if err != nil {
			return err
		}
	} else {
		// LoRaWAN 1.0.x
		ctx.joinAnsPayload.NwkSKey, err = backend.NewKeyEnvelope(ctx.nsKEKLabel, ctx.nsKEK, ctx.fNwkSIntKey)
		if err != nil {
			return err
		}
	}

	return nil
}
