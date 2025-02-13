package com.es.aplicacion.dto

import com.es.aplicacion.model.Direccion

data class UsuarioDTO(
    val username: String,
    val email: String,
    val rol: String?,
    val direccion: Direccion
)
