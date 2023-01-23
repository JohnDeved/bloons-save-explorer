import { useCallback, useState } from 'react'
import reactLogo from './assets/react.svg'
import './App.css'
import { fileOpen } from 'browser-fs-access'
import { deflate, inflate } from 'pako'

const BLOONS_DUMMY_HEADER_LENGTH = 44;
const BLOONS_SALT_LENGTH = 24;
const BLOONS_KEY_LENGTH = 16;
const BLOONS_IV_LENGTH = 16;
const BLOONS_DERIVE_ITERATIONS = 10;
const BLOONS_PASSWORD_INDEX = 2;
const BLOONS_COMPRESSION_LEVEL = 3;
const BLOONS_COMPRESSION_LOG2_BUFFER_SIZE = 11; // 2^11 == 2048

async function unpack(input: ArrayBuffer, password = '11') {
  // open input file
  const inputData = new Uint8Array(input)

  // read dummy header (44 bytes of garbage?)
  const dummyHeader = inputData.slice(0, BLOONS_DUMMY_HEADER_LENGTH)

  // read password index; not needed for Bloons TD 6
  const passwordIndex = inputData.slice(dummyHeader.length, dummyHeader.length + 8)

  // read salt
  const salt = inputData.slice(dummyHeader.length + passwordIndex.length, dummyHeader.length + passwordIndex.length + BLOONS_SALT_LENGTH)

  // derive key and iv from salt and password
  const raw = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: BLOONS_DERIVE_ITERATIONS, hash: 'SHA-1' },
    await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']),
    BLOONS_KEY_LENGTH * 8 + BLOONS_IV_LENGTH * 8
  )

  // set key and iv
  const iv = raw.slice(0, 16)
  const key = raw.slice(-16)

  // log key and iv as base64
  console.log('key', btoa(String.fromCharCode(...new Uint8Array(key))))
  console.log('iv', btoa(String.fromCharCode(...new Uint8Array(iv))))
  console.log({raw, key, iv, inputData, dummyHeader, passwordIndex, salt, input})

  // decrypt data
  const decryptedData = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt', 'decrypt']),
    inputData.slice(dummyHeader.length + passwordIndex.length + salt.length)
  )

  console.log({decryptedData})
  console.log('decryptedData', btoa(String.fromCharCode(...new Uint8Array(decryptedData))))
  // // decompress data
  const decompressedData = inflate(decryptedData)
  const dataString = new TextDecoder().decode(decompressedData)
  const dataJson = JSON.parse(dataString)
  console.log({ dataJson })
}

function App() {
  const handleClick = useCallback(async () => {
    const file = await fileOpen()
    const buffer = await file.arrayBuffer()
    console.log(file,buffer)
    const data = await unpack(buffer).catch(console.error)
    console.log(data)
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
