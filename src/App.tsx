import { useCallback, useState } from 'react'
import reactLogo from './assets/react.svg'
import './App.css'
import { fileOpen } from 'browser-fs-access'
import { deflate, inflate } from 'pako'

async function unpack(input: ArrayBuffer, password = '11') {
  // open input file
  const inputData = new Uint8Array(input)

  // read dummy header (44 bytes of garbage?)
  const dummyHeader = inputData.slice(0, 44)
  console.log('dummyHeader', dummyHeader)

  // read password index; not needed for Bloons TD 6
  const passwordIndex = inputData.slice(dummyHeader.length, dummyHeader.length + 8)
  console.log('passwordIndex', passwordIndex)

  // read salt
  const salt = inputData.slice(dummyHeader.length + passwordIndex.length, dummyHeader.length + passwordIndex.length + 24)

  console.log('header length', dummyHeader.length + passwordIndex.length + salt.length)

  // derive key and iv from salt and password
  const raw = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 10, hash: 'SHA-1' },
    await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']),
    256
  )

  // set key and iv
  const iv = raw.slice(0, 16)
  const key = raw.slice(-16)

  // decrypt data
  const decryptedData = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt', 'decrypt']),
    inputData.slice(dummyHeader.length + passwordIndex.length + salt.length)
  )

  // // decompress data
  const decompressedData = inflate(decryptedData)
  const dataString = new TextDecoder().decode(decompressedData)
  const data = JSON.parse(dataString)
  return { data, dataString, iv, key, salt, dummyHeader, passwordIndex }
}

async function pack (input: string, iv: ArrayBuffer, key: ArrayBuffer, salt: Uint8Array, dummyHeader: Uint8Array, passwordIndex: Uint8Array, password = '11') {
  // compress data
  const compressedData = deflate(input, {level: 3})

  // encrypt data
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt', 'decrypt']),
    compressedData
  )

  // write salt
  const saltData = new Uint8Array(salt)

  // write data
  const data = new Uint8Array(encryptedData)

  console.log('header length', dummyHeader.length + passwordIndex.length + saltData.length)

  // concatenate all data
  const output = new Uint8Array(dummyHeader.length + passwordIndex.length + saltData.length + data.length)
  output.set(dummyHeader)
  output.set(passwordIndex, dummyHeader.length)
  output.set(saltData, dummyHeader.length + passwordIndex.length)
  output.set(data, dummyHeader.length + passwordIndex.length + saltData.length)

  return output.buffer
}

function App() {
  const handleClick = useCallback(async () => {
    const file = await fileOpen()
    const buffer = await file.arrayBuffer()
    const data = await unpack(buffer)
    // console.log(data)
    const packed = await pack(data.dataString, data.iv, data.key, data.salt, data.dummyHeader, data.passwordIndex)
    console.log({packed, buffer})
    // log as base64
    // console.log(btoa(new Uint8Array(packed).reduce((data, byte) => data + String.fromCharCode(byte), '')))
    // console.log(btoa(new Uint8Array(buffer).reduce((data, byte) => data + String.fromCharCode(byte), '')))
  }, [])

  return (
    <div className="App">
      <div>
        <a href="https://vitejs.dev" target="_blank">
          <img src="/vite.svg" className="logo" alt="Vite logo" />
        </a>
        <a href="https://reactjs.org" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>Vite + React</h1>
      <div className="card">
        <button onClick={handleClick}>
          open file
        </button>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
      </div>
      <p className="read-the-docs">
        Click on the Vite and React logos to learn more
      </p>
    </div>
  )
}

export default App
