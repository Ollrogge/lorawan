package joinserver

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/brocaar/lorawan"
	"github.com/pkg/errors"

	"github.com/brocaar/lorawan/backend"
)

var joinTasks = []func(*context) error{
	setJoinContext,
	validateMIC,
	setJoinNonce,
	doFidoStuff,
	setSessionKeys,
	createJoinAnsPayload,
}

var fidoJoinTasks = []func(*context) error{
	setJoinNonce,
	doFidoStuff,
	setRootKeys,
	createFidoJoinAnsPayload,
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
	FidoData []byte `json:"fidoData"`
}

func doFidoStuff(ctx *context) error {
	if len(ctx.fidoData.Bytes) == 0x0 {
		return nil
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

	// 0x0 to indicate join_accept_1 msg
	fidoResp.FidoData = append([]byte{0x0}, fidoResp.FidoData...)

	ctx.fidoData.Bytes = fidoResp.FidoData

	//log.Println("Fido http response: ", fidoResp)

	return nil
}

func setRootKeys(ctx *context) error {

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

// join-accept_1
func createFidoJoinAnsPayload(ctx *context) error {
	phy := lorawan.PHYPayload{
		MHDR: lorawan.MHDR{
			MType: lorawan.JoinAccept,
			Major: lorawan.LoRaWANR1,
		},
		MACPayload: &lorawan.DataPayload{
			Bytes: ctx.fidoData.Bytes,
		},
	}

	if ctx.joinReqPayload.DLSettings.OptNeg {
		jsIntKey, err := getJSIntKey(ctx.deviceKeys.NwkKey, ctx.devEUI)
		if err != nil {
			return err
		}
		if err := phy.SetFidoDownlinkJoinMIC(&ctx.fidoData, jsIntKey); err != nil {
			return err
		}
	} else {
		if err := phy.SetFidoDownlinkJoinMIC(&ctx.fidoData, ctx.deviceKeys.NwkKey); err != nil {
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

	ctx.joinAnsPayload = backend.JoinAnsPayload{
		BasePayloadResult: backend.BasePayloadResult{
			Result: backend.Result{
				ResultCode: backend.Success,
			},
		},
		PHYPayload: backend.HEXBytes(b),
		// TODO add Lifetime?
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

func createJoinAnsPayload(ctx *context) error {
	var cFList *lorawan.CFList
	if len(ctx.joinReqPayload.CFList[:]) != 0 {
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

	ctx.joinAnsPayload = backend.JoinAnsPayload{
		BasePayloadResult: backend.BasePayloadResult{
			Result: backend.Result{
				ResultCode: backend.Success,
			},
		},
		PHYPayload: backend.HEXBytes(b),
		// TODO add Lifetime?
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
