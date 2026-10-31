//! RFC-ILP-2026: Interaction Layer Protocol - Transport & Network Framing Module
//!
//! Este módulo implementa la capa de transporte sobre streams de I/O (`std::net::TcpStream`,
//! Unix Domain Sockets o cualquier stream que implemente `Read + Write`).
//!
//! Garantiza el encuadre determinista (framing) de tramas I-PDU:
//! 1. Lectura obligatoria de los 36 bytes de cabecera canónica (`IpduHeader`).
//! 2. Lectura y verificación de los 4 bytes de prefijo de longitud (`Length-Prefix`).
//! 3. Blindaje contra ataques de agotamiento de memoria (OOM / Allocation Bomb) verificando cotas (`<= 64KB`).
//! 4. Lectura exacta de la carga útil semántica (`payload`).

use crate::ipdu::header::{IpduError, IpduHeader, CANONICAL_HEADER_SIZE};
use crate::ipdu::packet::{IpduPacket, MAX_ILP_PAYLOAD_SIZE};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

/// Stream de comunicación de Capa 8 que serializa y deserializa paquetes `IpduPacket`
/// directamente sobre un canal de transmisión subyacente.
#[derive(Debug)]
pub struct IlpStream<S> {
    inner: S,
}

impl<S> IlpStream<S> {
    /// Envuelve un stream existente en un `IlpStream`.
    pub fn new(stream: S) -> Self {
        Self { inner: stream }
    }

    /// Retorna una referencia inmutable al stream subyacente.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Retorna una referencia mutable al stream subyacente.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume el wrapper y retorna el stream subyacente.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl IlpStream<TcpStream> {
    /// Establece una conexión TCP saliente hacia la dirección indicada y la envuelve en `IlpStream`.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, IpduError> {
        let stream = TcpStream::connect(addr)?;
        Ok(Self::new(stream))
    }
}

impl<S: Read + Write> IlpStream<S> {
    /// Envía un paquete I-PDU completo a través del stream.
    ///
    /// Formato transmitido en red:
    /// `[36 bytes Header Canónico] [4 bytes Payload Length Big-Endian] [N bytes Payload]`
    pub fn send_packet(&mut self, packet: &IpduPacket) -> Result<(), IpduError> {
        let wire_bytes = packet.to_bytes();
        self.inner.write_all(&wire_bytes)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Recibe un paquete I-PDU completo desde el stream validando cotas y estructura.
    ///
    /// Si el stream se cierra de manera limpia antes de recibir datos, retorna `Err(IpduError::ConnectionClosed)`.
    /// Si el payload declarado excede `MAX_ILP_PAYLOAD_SIZE`, se aborta inmediatamente sin reservar memoria.
    pub fn recv_packet(&mut self) -> Result<IpduPacket, IpduError> {
        // 1. Leer los 36 bytes de la cabecera canónica
        let mut header_buf = [0u8; CANONICAL_HEADER_SIZE];
        match self.inner.read_exact(&mut header_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(IpduError::ConnectionClosed);
            }
            Err(e) => return Err(IpduError::from(e)),
        }

        let header = IpduHeader::from_canonical_bytes(&header_buf)?;

        // 2. Leer los 4 bytes del prefijo de longitud (Big-Endian)
        let mut len_buf = [0u8; 4];
        self.inner.read_exact(&mut len_buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                IpduError::TruncatedPayload {
                    expected: CANONICAL_HEADER_SIZE + 4,
                    actual: CANONICAL_HEADER_SIZE,
                }
            } else {
                IpduError::from(e)
            }
        })?;

        let payload_len = u32::from_be_bytes(len_buf) as usize;

        // 3. Defensa estricta contra Allocation Bomb (OOM)
        if payload_len > MAX_ILP_PAYLOAD_SIZE {
            return Err(IpduError::PayloadTooLarge(payload_len));
        }

        // 4. Leer exactamente el payload declarado
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            self.inner.read_exact(&mut payload).map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    IpduError::TruncatedPayload {
                        expected: CANONICAL_HEADER_SIZE + 4 + payload_len,
                        actual: CANONICAL_HEADER_SIZE + 4,
                    }
                } else {
                    IpduError::from(e)
                }
            })?;
        }

        Ok(IpduPacket::new(header, payload))
    }
}
