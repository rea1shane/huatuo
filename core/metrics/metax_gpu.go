// Copyright 2025 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

/*
#include "stdio.h"
#include "stdlib.h"
#include "memory.h"
#include "MxSmlMcm.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"strconv"

	"huatuo-bamai/pkg/metric"
	"huatuo-bamai/pkg/tracing"
)

type metaxGpuCollector struct{}

func init() {
	tracing.RegisterEventTracing("metax_gpu", newMetaxGpuCollector)
}

func newMetaxGpuCollector() (*tracing.EventTracingAttr, error) {
	// Init MetaX SML
	if err := metaxSmlInit(); err != nil {
		return nil, fmt.Errorf("failed to init sml: %v", err)
	}

	return &tracing.EventTracingAttr{
		TracingData: &metaxGpuCollector{},
		Flag:        tracing.FlagMetric,
	}, nil
}

func (m *metaxGpuCollector) Update() ([]*metric.Data, error) {
	var metrics []*metric.Data

	// MACA version
	if macaVersion, err := metaxSmlGetMacaVersion(); metaxIsSmlOperationNotSupportedError(err) {

	} else if err != nil {
		return nil, fmt.Errorf("failed to get maca version: %v", err)
	} else {

	}

	var gpus []int

	// Native and VF GPUs
	nativeAndVfGpuCount := metaxSmlGetNativeAndVfGpuCount()
	for i := 0; i < nativeAndVfGpuCount; i++ {
		gpus = append(gpus, i)
	}

	// PF GPUs
	pfGpuCount := metaxSmlGetPfGpuCount()
	for i := 100; i < 100+pfGpuCount; i++ {
		gpus = append(gpus, i)
	}

	// Metrics
	for _, gpu := range gpus {
		gpuMetrics, err := metaxGetGpuMetrics(gpu)
		if err != nil {
			return nil, fmt.Errorf("failed to get gpu %d metrics: %v", gpu, err)
		}
		metrics = append(metrics, gpuMetrics...)
	}

	return metrics, nil
}

func metaxGetGpuMetrics(gpu int) ([]*metric.Data, error) {
	var metrics []*metric.Data

	// GPU info
	gpuInfo, err := metaxSmlGetGpuInfo(gpu)
	if err != nil {
		return nil, fmt.Errorf("failed to get gpu info: %v", err)
	}
	metrics = append(metrics,
		metric.NewGaugeData("info", 1, "GPU info.", map[string]string{
			"gpu":       strconv.Itoa(gpu),
			"series":    string(gpuInfo.series),
			"model":     gpuInfo.model,
			"uuid":      gpuInfo.uuid,
			"bdf":       gpuInfo.bdf,
			"mode":      string(gpuInfo.mode),
			"die_count": strconv.Itoa(gpuInfo.dieCount),
		}),
	)

	// Board electric infos
	if boardWayElectricInfos, err := metaxSmlListGpuBoardWayElectricInfos(gpu); metaxIsSmlOperationNotSupportedError(err) {

	} else if err != nil {
		return nil, fmt.Errorf("failed to list board way electric infos: %v", err)
	} else {
		for i, info := range boardWayElectricInfos {
			metrics = append(metrics,
				metric.NewGaugeData("board_voltage_volts", info.voltage/1000, "Voltage of each power supply of the GPU board.", map[string]string{
					"gpu": strconv.Itoa(gpu),
					"way": strconv.Itoa(i),
				}),
				metric.NewGaugeData("board_current_amperes", info.current/1000, "Current of each power supply of the GPU board.", map[string]string{
					"gpu": strconv.Itoa(gpu),
					"way": strconv.Itoa(i),
				}),
				metric.NewGaugeData("board_power_watts", info.power/1000, "Power of each power supply of the GPU board.", map[string]string{
					"gpu": strconv.Itoa(gpu),
					"way": strconv.Itoa(i),
				}),
			)
		}
	}

	// PCIe link
	if pcieLinkInfo, err := metaxSmlGetGpuPcieLinkInfo(gpu); metaxIsSmlOperationNotSupportedError(err) {

	} else if err != nil {
		return nil, fmt.Errorf("failed to get pcie link info: %v", err)
	} else {
		metrics = append(metrics,
			metric.NewGaugeData("pcie_link_speed_transfers_per_second", pcieLinkInfo.speed*1000*1000*1000, "GPU PCIe current link speed.", map[string]string{
				"gpu": strconv.Itoa(gpu),
			}),
			metric.NewGaugeData("pcie_link_width_lanes", pcieLinkInfo.width, "GPU PCIe current link width.", map[string]string{
				"gpu": strconv.Itoa(gpu),
			}),
		)
	}

	if pcieLinkMaxInfo, err := metaxSmlGetGpuPcieLinkMaxInfo(gpu); metaxIsSmlOperationNotSupportedError(err) {

	} else if err != nil {
		return nil, fmt.Errorf("failed to get pcie link mx info: %v", err)
	} else {
		metrics = append(metrics,
			metric.NewGaugeData("pcie_link_speed_max_transfers_per_second", pcieLinkMaxInfo.speed*1000*1000*1000, "GPU PCIe max link speed.", map[string]string{
				"gpu": strconv.Itoa(gpu),
			}),
			metric.NewGaugeData("pcie_link_width_max_lanes", pcieLinkMaxInfo.width, "GPU PCIe max link width.", map[string]string{
				"gpu": strconv.Itoa(gpu),
			}),
		)
	}

	// PCIe throughput
	if pcieThroughputInfo, err := metaxSmlGetGpuPcieThroughputInfo(gpu); metaxIsSmlOperationNotSupportedError(err) {

	} else if err != nil {
		return nil, fmt.Errorf("failed to get pcie throughput info: %v", err)
	} else {
		metrics = append(metrics,
			metric.NewGaugeData("pcie_throughput_receive_bytes_per_second", pcieThroughputInfo.receiveRate*1000*1000, "GPU PCIe receive throughput.", map[string]string{
				"gpu": strconv.Itoa(gpu),
			}),
			metric.NewGaugeData("pcie_throughput_transmit_bytes_per_second", pcieThroughputInfo.transmitRate*1000*1000, "GPU PCIe transmit throughput.", map[string]string{
				"gpu": strconv.Itoa(gpu),
			}),
		)
	}

	// MetaXLink
	if metaxlinkLinkInfos, err := metaxSmlListGpuMetaxlinkLinkInfos(gpu); metaxIsSmlOperationNotSupportedError(err) {

	} else if err != nil {
		return nil, fmt.Errorf("failed to list metaxlink link infos: %v", err)
	} else {
		for i, info := range metaxlinkLinkInfos {
			metrics = append(metrics,
				metric.NewGaugeData("metaxlink_link_speed_transfers_per_second", info.speed*1000*1000*1000, "GPU MetaXLink current link speed.", map[string]string{
					"gpu":       strconv.Itoa(gpu),
					"metaxlink": strconv.Itoa(i),
				}),
				metric.NewGaugeData("metaxlink_link_width_lanes", info.width, "GPU MetaXLink current link width.", map[string]string{
					"gpu":       strconv.Itoa(gpu),
					"metaxlink": strconv.Itoa(i),
				}),
			)
		}
	}

	// MetaXLink throughput
	if metaxlinkThroughputInfos, err := metaxSmlListGpuMetaxlinkThroughputInfos(gpu); metaxIsSmlOperationNotSupportedError(err) {

	} else if err != nil {
		return nil, fmt.Errorf("failed to list metaxlink throughput infos: %v", err)
	} else {
		for i, info := range metaxlinkThroughputInfos {
			metrics = append(metrics,
				metric.NewGaugeData("metaxlink_throughput_receive_bytes_per_second", info.receiveRate*1000*1000, "GPU MetaXLink receive throughput.", map[string]string{
					"gpu":       strconv.Itoa(gpu),
					"metaxlink": strconv.Itoa(i),
				}),
				metric.NewGaugeData("metaxlink_throughput_transmit_bytes_per_second", info.transmitRate*1000*1000, "GPU MetaXLink transmit throughput.", map[string]string{
					"gpu":       strconv.Itoa(gpu),
					"metaxlink": strconv.Itoa(i),
				}),
			)
		}
	}

	// Die
	for die := 0; die < gpuInfo.dieCount; die++ {
		dieMetrics, err := metaxGetDieMetrics(gpu, die, gpuInfo.series)
		if err != nil {
			return nil, fmt.Errorf("failed to get die %d metrics: %v", die, err)
		}
		metrics = append(metrics, dieMetrics...)
	}

	return metrics, nil
}

/*
  Die metrics
*/

var (
	metaxTemperatureSensorMap = map[string]C.mxSmlTemperatureSensors_t{
		"chip_hotspot": C.MXSML_Temperature_Hotspot,
	}
	metaxUtilizationIpMap = map[string]C.mxSmlUsageIp_t{
		"vpue":  C.MXSML_Usage_Vpue,
		"vpud":  C.MXSML_Usage_Vpud,
		"xcore": C.MXSML_Usage_Xcore,
	}
	metaxClockIpMap = map[string]C.mxSmlClockIp_t{
		"vpue":   C.MXSML_Clock_Vpue,
		"vpud":   C.MXSML_Clock_Vpud,
		"xcore":  C.MXSML_Clock_Xcore,
		"memory": C.MXSML_Clock_Mc0,
	}
)

func metaxGetDieMetrics(gpu, die int, series metaxGpuSeries) ([]*metric.Data, error) {
	var metrics []*metric.Data

	// Temperature
	for sensor, sensorC := range metaxTemperatureSensorMap {
		if value, err := metaxSmlGetDieTemperature(gpu, die, sensorC); metaxIsSmlOperationNotSupportedError(err) {

		} else if err != nil {
			return nil, fmt.Errorf("failed to get %s temperature: %v", sensor, err)
		} else {
			metrics = append(metrics,
				metric.NewGaugeData("temperature_celsius", value, "Temperature of each GPU sensor.", map[string]string{
					"gpu":    strconv.Itoa(gpu),
					"die":    strconv.Itoa(die),
					"sensor": sensor,
				}),
			)
		}
	}

	// Utilization
	for ip, ipC := range metaxUtilizationIpMap {
		if value, err := metaxSmlGetDieUtilization(gpu, die, ipC); metaxIsSmlOperationNotSupportedError(err) {

		} else if err != nil {
			return nil, fmt.Errorf("failed to get %s utilization: %v", ip, err)
		} else {
			metrics = append(metrics,
				metric.NewGaugeData("utilization_percent", value, "GPU utilization, ranging from 0 to 100.", map[string]string{
					"gpu": strconv.Itoa(gpu),
					"die": strconv.Itoa(die),
					"ip":  ip,
				}),
			)
		}
	}

	// Memory
	if memoryInfo, err := metaxSmlGetDieMemoryInfo(gpu, die); metaxIsSmlOperationNotSupportedError(err) {

	} else if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %v", err)
	} else {
		metrics = append(metrics,
			metric.NewGaugeData("memory_total_bytes", float64(memoryInfo.total)*1000, "Total vram.", map[string]string{
				"gpu": strconv.Itoa(gpu),
				"die": strconv.Itoa(die),
			}),
			metric.NewGaugeData("memory_used_bytes", float64(memoryInfo.used)*1000, "Used vram.", map[string]string{
				"gpu": strconv.Itoa(gpu),
				"die": strconv.Itoa(die),
			}),
		)
	}

	// Clock
	for ip, ipC := range metaxClockIpMap {
		// SPECIAL >>
		if ip == "memory" && series == metaxGpuSeriesN {
			ipC = C.MXSML_Clock_Mc
		}
		// << END

		if values, err := metaxSmlListDieClocks(gpu, die, ipC); metaxIsSmlOperationNotSupportedError(err) {

		} else if err != nil {
			return nil, fmt.Errorf("failed to list %s clocks: %v", ip, err)
		} else {
			metrics = append(metrics,
				metric.NewGaugeData("clock_hertz", values[0]*1000*1000, "GPU clock.", map[string]string{
					"gpu": strconv.Itoa(gpu),
					"die": strconv.Itoa(die),
					"ip":  ip,
				}),
			)
		}
	}

	return metrics, nil
}

/*
  MetaX SML call
*/

var metaxSmlOperationNotSupportedErr = errors.New("operation not supported")

func metaxIsSmlOperationNotSupportedError(err error) bool {
	return errors.Is(err, metaxSmlOperationNotSupportedErr)
}

const (
	metaxSmlReturnCodeSuccess               = C.MXSML_Success
	metaxSmlReturnCodeOperationNotSupported = C.MXSML_OperationNotSupport
)

/*
  Init
*/

func metaxSmlInit() error {
	if returnCode := C.mxSmlInit(); returnCode != metaxSmlReturnCodeSuccess {
		return fmt.Errorf("mxSmlInit failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	return nil
}

/*
  Basic
*/

func metaxSmlGetMacaVersion() (string, error) {
	var versionLen C.uint = 128

	buf := C.malloc(C.size_t(versionLen))
	if buf == nil {
		return "", fmt.Errorf("malloc failed")
	}
	defer C.free(buf)

	if returnCode := C.mxSmlGetMacaVersion((*C.char)(buf), &versionLen); returnCode == metaxSmlReturnCodeOperationNotSupported {
		return "", metaxSmlOperationNotSupportedErr
	} else if returnCode != metaxSmlReturnCodeSuccess {
		return "", fmt.Errorf("mxSmlGetMacaVersion failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	version := C.GoString((*C.char)(buf))
	return version, nil
}

func metaxSmlGetNativeAndVfGpuCount() int {
	return int(C.mxSmlGetDeviceCount())
}

func metaxSmlGetPfGpuCount() int {
	return int(C.mxSmlGetPfDeviceCount())
}

/*
  GPU
*/

type metaxGpuInfo struct {
	series   metaxGpuSeries
	model    string
	uuid     string
	bdf      string
	mode     metaxGpuMode
	dieCount int
}

type metaxGpuSeries string

const (
	metaxSmlGpuBrandUnknown = C.MXSML_Brand_Unknown
	metaxSmlGpuBrandN       = C.MXSML_Brand_N
	metaxSmlGpuBrandC       = C.MXSML_Brand_C
	metaxSmlGpuBrandG       = C.MXSML_Brand_G

	metaxGpuSeriesUnknown metaxGpuSeries = "unknown"
	metaxGpuSeriesN       metaxGpuSeries = "mxn"
	metaxGpuSeriesC       metaxGpuSeries = "mxc"
	metaxGpuSeriesG       metaxGpuSeries = "mxg"
)

type metaxGpuMode string

const (
	metaxSmlGpuModeNative = C.MXSML_Virtualization_Mode_None
	metaxSmlGpuModePf     = C.MXSML_Virtualization_Mode_Pf
	metaxSmlGpuModeVf     = C.MXSML_Virtualization_Mode_Vf

	metaxGpuModeNative metaxGpuMode = "native"
	metaxGpuModePf     metaxGpuMode = "pf"
	metaxGpuModeVf     metaxGpuMode = "vf"
)

func metaxSmlGetGpuInfo(gpu int) (metaxGpuInfo, error) {
	var deviceInfo C.mxSmlDeviceInfo_t
	if returnCode := C.mxSmlGetDeviceInfo(C.uint(gpu), &deviceInfo); returnCode != metaxSmlReturnCodeSuccess {
		return metaxGpuInfo{}, fmt.Errorf("mxSmlGetDeviceInfo failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	var series metaxGpuSeries
	switch deviceInfo.brand {
	case metaxSmlGpuBrandUnknown:
		series = metaxGpuSeriesUnknown
	case metaxSmlGpuBrandN:
		series = metaxGpuSeriesN
	case metaxSmlGpuBrandC:
		series = metaxGpuSeriesC
	case metaxSmlGpuBrandG:
		series = metaxGpuSeriesG
	default:
		return metaxGpuInfo{}, fmt.Errorf("invalid gpu series: %v", deviceInfo.brand)
	}

	var mode metaxGpuMode
	switch deviceInfo.mode {
	case metaxSmlGpuModeNative:
		mode = metaxGpuModeNative
	case metaxSmlGpuModePf:
		mode = metaxGpuModePf
	case metaxSmlGpuModeVf:
		mode = metaxGpuModeVf
	default:
		return metaxGpuInfo{}, fmt.Errorf("invalid gpu mode: %v", deviceInfo.mode)
	}

	var dieCount C.uint
	if returnCode := C.mxSmlGetDeviceDieCount(C.uint(gpu), &dieCount); returnCode != metaxSmlReturnCodeSuccess {
		return metaxGpuInfo{}, fmt.Errorf("mxSmlGetDeviceDieCount failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	return metaxGpuInfo{
		series:   series,
		model:    C.GoString(&(deviceInfo.deviceName[0])),
		uuid:     C.GoString(&(deviceInfo.uuid[0])),
		bdf:      C.GoString(&(deviceInfo.bdfId[0])),
		mode:     mode,
		dieCount: int(dieCount),
	}, nil
}

type metaxGpuBoardWayElectricInfo struct {
	voltage float64 // voltage in mV.
	current float64 // current in mA.
	power   float64 // power in mW.
}

func metaxSmlListGpuBoardWayElectricInfos(gpu int) ([]metaxGpuBoardWayElectricInfo, error) {
	const maxBoardWays = 3

	arr := make([]C.mxSmlBoardWayElectricInfo_t, maxBoardWays)
	size := C.uint(maxBoardWays)

	if returnCode := C.mxSmlGetBoardPowerInfo(C.uint(gpu), &size, &arr[0]); returnCode == metaxSmlReturnCodeOperationNotSupported {
		return nil, metaxSmlOperationNotSupportedErr
	} else if returnCode != metaxSmlReturnCodeSuccess {
		return nil, fmt.Errorf("mxSmlGetBoardPowerInfo failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	actualSize := int(size)
	result := make([]metaxGpuBoardWayElectricInfo, actualSize)

	for i := 0; i < actualSize; i++ {
		result[i] = metaxGpuBoardWayElectricInfo{
			voltage: float64(arr[i].voltage),
			current: float64(arr[i].current),
			power:   float64(arr[i].power),
		}
	}

	return result, nil
}

/*
  PCIe
*/

type metaxGpuPcieLinkInfo struct {
	speed float64 // speed in GT/s.
	width float64 // width in lanes.
}

func metaxSmlGetGpuPcieLinkInfo(gpu int) (metaxGpuPcieLinkInfo, error) {
	var pcieInfo C.mxSmlPcieInfo_t
	if returnCode := C.mxSmlGetPcieInfo(C.uint(gpu), &pcieInfo); returnCode == metaxSmlReturnCodeOperationNotSupported {
		return metaxGpuPcieLinkInfo{}, metaxSmlOperationNotSupportedErr
	} else if returnCode != metaxSmlReturnCodeSuccess {
		return metaxGpuPcieLinkInfo{}, fmt.Errorf("mxSmlGetPcieInfo failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	return metaxGpuPcieLinkInfo{
		speed: float64(pcieInfo.speed),
		width: float64(pcieInfo.width),
	}, nil
}

func metaxSmlGetGpuPcieLinkMaxInfo(gpu int) (metaxGpuPcieLinkInfo, error) {
	var pcieInfo C.mxSmlPcieInfo_t
	if returnCode := C.mxSmlGetPcieMaxLinkInfo(C.uint(gpu), &pcieInfo); returnCode == metaxSmlReturnCodeOperationNotSupported {
		return metaxGpuPcieLinkInfo{}, metaxSmlOperationNotSupportedErr
	} else if returnCode != metaxSmlReturnCodeSuccess {
		return metaxGpuPcieLinkInfo{}, fmt.Errorf("mxSmlGetPcieMaxLinkInfo failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	return metaxGpuPcieLinkInfo{
		speed: float64(pcieInfo.speed),
		width: float64(pcieInfo.width),
	}, nil
}

// metaxGpuPcieThroughputInfo in MB/s.
type metaxGpuPcieThroughputInfo struct {
	receiveRate  float64
	transmitRate float64
}

func metaxSmlGetGpuPcieThroughputInfo(gpu int) (metaxGpuPcieThroughputInfo, error) {
	var pcieThroughput C.mxSmlPcieThroughput_t
	if returnCode := C.mxSmlGetPcieThroughput(C.uint(gpu), &pcieThroughput); returnCode == metaxSmlReturnCodeOperationNotSupported {
		return metaxGpuPcieThroughputInfo{}, metaxSmlOperationNotSupportedErr
	} else if returnCode != metaxSmlReturnCodeSuccess {
		return metaxGpuPcieThroughputInfo{}, fmt.Errorf("mxSmlGetPcieThroughput failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	return metaxGpuPcieThroughputInfo{
		receiveRate:  float64(pcieThroughput.rx),
		transmitRate: float64(pcieThroughput.tx),
	}, nil
}

/*
  MetaXLink
*/

const (
	metaxGpuMetaxlinkMaxNumber                           = 7
	metaxGpuMetaxlinkTypeReceive  C.mxSmlMetaXLinkType_t = C.MXSML_MetaXLink_Input
	metaxGpuMetaxlinkTypeTransmit C.mxSmlMetaXLinkType_t = C.MXSML_MetaXLink_Target
)

type metaxGpuMetaxlinkLinkInfo struct {
	speed float64 // speed in GT/s.
	width float64 // width in lanes.
}

func metaxSmlListGpuMetaxlinkLinkInfos(gpu int) ([]metaxGpuMetaxlinkLinkInfo, error) {
	arr := make([]C.mxSmlSingleMxlkInfo_t, metaxGpuMetaxlinkMaxNumber)
	size := C.uint(metaxGpuMetaxlinkMaxNumber)

	if returnCode := C.mxSmlGetMetaXLinkInfo_v2(C.uint(gpu), &size, &arr[0]); returnCode == metaxSmlReturnCodeOperationNotSupported {
		return nil, metaxSmlOperationNotSupportedErr
	} else if returnCode != metaxSmlReturnCodeSuccess {
		return nil, fmt.Errorf("mxSmlGetMetaXLinkInfo_v2 failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	actualSize := int(size)
	result := make([]metaxGpuMetaxlinkLinkInfo, actualSize)

	for i := 0; i < actualSize; i++ {
		result[i] = metaxGpuMetaxlinkLinkInfo{
			speed: float64(arr[i].speed),
			width: float64(arr[i].width),
		}
	}

	return result, nil
}

// metaxGpuMetaxlinkThroughputInfo in MB/s.
type metaxGpuMetaxlinkThroughputInfo struct {
	receiveRate  float64
	transmitRate float64
}

func metaxSmlListGpuMetaxlinkThroughputInfos(gpu int) ([]metaxGpuMetaxlinkThroughputInfo, error) {
	receiveRates, err := metaxSmlListGpuMetaxlinkThroughputParts(gpu, metaxGpuMetaxlinkTypeReceive)
	if metaxIsSmlOperationNotSupportedError(err) {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("failed to list metaxlink receive rates: %v", err)
	}

	transmitRates, err := metaxSmlListGpuMetaxlinkThroughputParts(gpu, metaxGpuMetaxlinkTypeTransmit)
	if metaxIsSmlOperationNotSupportedError(err) {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("failed to list metaxlink transmit rates: %v", err)
	}

	if len(receiveRates) != len(transmitRates) {
		return nil, fmt.Errorf("receive and transmit array length mismatch")
	}

	result := make([]metaxGpuMetaxlinkThroughputInfo, len(receiveRates))

	for i := 0; i < len(result); i++ {
		result[i] = metaxGpuMetaxlinkThroughputInfo{
			receiveRate:  receiveRates[i],
			transmitRate: transmitRates[i],
		}
	}

	return result, nil
}

func metaxSmlListGpuMetaxlinkThroughputParts(gpu int, typ C.mxSmlMetaXLinkType_t) ([]float64, error) {
	arr := make([]C.mxSmlMetaXLinkBandwidth_t, metaxGpuMetaxlinkMaxNumber)
	size := C.uint(metaxGpuMetaxlinkMaxNumber)

	if returnCode := C.mxSmlGetMetaXLinkBandwidth(C.uint(gpu), typ, &size, &arr[0]); returnCode == metaxSmlReturnCodeOperationNotSupported {
		return nil, metaxSmlOperationNotSupportedErr
	} else if returnCode != metaxSmlReturnCodeSuccess {
		return nil, fmt.Errorf("mxSmlGetMetaXLinkBandwidth failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	actualSize := int(size)
	result := make([]float64, actualSize)

	for i := 0; i < actualSize; i++ {
		result[i] = float64(arr[i].requestBandwidth)
	}

	return result, nil
}

// metaxGpuMetaxlinkTrafficStatInfo in B.
type metaxGpuMetaxlinkTrafficStatInfo struct {
	receive  float64
	transmit float64
}

func metaxSmlListGpuMetaxlinkTrafficStatInfos(gpu int) ([]metaxGpuMetaxlinkTrafficStatInfo, error) {
	receives, err := metaxSmlListGpuMetaxlinkTrafficStatParts(gpu, metaxGpuMetaxlinkTypeReceive)
	if metaxIsSmlOperationNotSupportedError(err) {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("failed to list metaxlink receives: %v", err)
	}

	transmits, err := metaxSmlListGpuMetaxlinkTrafficStatParts(gpu, metaxGpuMetaxlinkTypeTransmit)
	if metaxIsSmlOperationNotSupportedError(err) {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("failed to list metaxlink transmits: %v", err)
	}

	if len(receives) != len(transmits) {
		return nil, fmt.Errorf("receive and transmit array length mismatch")
	}

	result := make([]metaxGpuMetaxlinkTrafficStatInfo, len(receives))

	for i := 0; i < len(result); i++ {
		result[i] = metaxGpuMetaxlinkTrafficStatInfo{
			receive:  receives[i],
			transmit: transmits[i],
		}
	}

	return result, nil
}

func metaxSmlListGpuMetaxlinkTrafficStatParts(gpu int, typ C.mxSmlMetaXLinkType_t) ([]float64, error) {
	arr := make([]C.mxSmlMetaXLinkTrafficStat_t, metaxGpuMetaxlinkMaxNumber)
	size := C.uint(metaxGpuMetaxlinkMaxNumber)

	if returnCode := C.mxSmlGetMetaXLinkTrafficStat(C.uint(gpu), typ, &size, &arr[0]); returnCode == metaxSmlReturnCodeOperationNotSupported {
		return nil, metaxSmlOperationNotSupportedErr
	} else if returnCode != metaxSmlReturnCodeSuccess {
		return nil, fmt.Errorf("mxSmlGetMetaXLinkTrafficStat failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	actualSize := int(size)
	result := make([]float64, actualSize)

	for i := 0; i < actualSize; i++ {
		result[i] = float64(arr[i].requestTrafficStat)
	}

	return result, nil
}

/*
  Die
*/

// metaxSmlGetDieTemperature in ℃.
func metaxSmlGetDieTemperature(gpu, die int, sensor C.mxSmlTemperatureSensors_t) (float64, error) {
	var value C.int

	if returnCode := C.mxSmlGetDieTemperatureInfo(C.uint(gpu), C.uint(die), sensor, &value); returnCode == metaxSmlReturnCodeOperationNotSupported {
		return 0, metaxSmlOperationNotSupportedErr
	} else if returnCode != metaxSmlReturnCodeSuccess {
		return 0, fmt.Errorf("mxSmlGetDieTemperatureInfo failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	return float64(value) / 100, nil
}

// metaxSmlGetDieUtilization in [0, 100].
func metaxSmlGetDieUtilization(gpu, die int, ip C.mxSmlUsageIp_t) (float64, error) {
	var value C.int

	if returnCode := C.mxSmlGetDieIpUsage(C.uint(gpu), C.uint(die), ip, &value); returnCode == metaxSmlReturnCodeOperationNotSupported {
		return 0, metaxSmlOperationNotSupportedErr
	} else if returnCode != metaxSmlReturnCodeSuccess {
		return 0, fmt.Errorf("mxSmlGetDieIpUsage failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	return float64(value), nil
}

// metaxDieMemoryInfo in KB.
type metaxDieMemoryInfo struct {
	total int64
	used  int64
}

func metaxSmlGetDieMemoryInfo(gpu, die int) (metaxDieMemoryInfo, error) {
	var memoryInfo C.mxSmlMemoryInfo_t
	if returnCode := C.mxSmlGetDieMemoryInfo(C.uint(gpu), C.uint(die), &memoryInfo); returnCode == metaxSmlReturnCodeOperationNotSupported {
		return metaxDieMemoryInfo{}, metaxSmlOperationNotSupportedErr
	} else if returnCode != metaxSmlReturnCodeSuccess {
		return metaxDieMemoryInfo{}, fmt.Errorf("mxSmlGetDieMemoryInfo failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	return metaxDieMemoryInfo{
		total: int64(memoryInfo.vramTotal),
		used:  int64(memoryInfo.vramUse),
	}, nil
}

// metaxSmlListDieClocks in MHz.
func metaxSmlListDieClocks(gpu, die int, ip C.mxSmlClockIp_t) ([]float64, error) {
	const maxClocksSize = 8

	arr := make([]C.uint, maxClocksSize)
	size := C.uint(maxClocksSize)

	if returnCode := C.mxSmlGetDieClocks(C.uint(gpu), C.uint(die), ip, &size, &arr[0]); returnCode == metaxSmlReturnCodeOperationNotSupported {
		return nil, metaxSmlOperationNotSupportedErr
	} else if returnCode != metaxSmlReturnCodeSuccess {
		return nil, fmt.Errorf("mxSmlGetDieClocks failed: %s", C.GoString(C.mxSmlGetErrorString(returnCode)))
	}

	actualSize := int(size)
	result := make([]float64, actualSize)

	for i := 0; i < actualSize; i++ {
		result[i] = float64(arr[i])
	}

	return result, nil
}
