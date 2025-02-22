package pvm

const BytesInPage = (1 << 12)

const BytesInRam = (1 << 32)

const NumRamPages = BytesInRam / BytesInPage

var MinValidRamIndex RamIndex = (1 << 16)
