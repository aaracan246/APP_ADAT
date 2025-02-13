package com.es.aplicacion.service

import com.es.aplicacion.dto.UsuarioDTO
import com.es.aplicacion.dto.UsuarioRegisterDTO
import com.es.aplicacion.error.exception.UnauthorizedException
import com.es.aplicacion.model.Usuario
import com.es.aplicacion.repository.UsuarioRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.stereotype.Service

@Service
class UsuarioService : UserDetailsService {

    @Autowired
    private lateinit var usuarioRepository: UsuarioRepository
    @Autowired
    private lateinit var passwordEncoder: PasswordEncoder


    override fun loadUserByUsername(username: String?): UserDetails {
        var usuario: Usuario = usuarioRepository
            .findByUsername(username!!)
            .orElseThrow {
                UnauthorizedException("$username no existente")
            }

        return User.builder()
            .username(usuario.username)
            .password(usuario.password)
            .roles(usuario.roles)
            .build()
    }

    fun insertUser(usuarioInsertadoDTO: UsuarioRegisterDTO) : UsuarioDTO? {

        if (usuarioRepository.findByUsername(usuarioInsertadoDTO.username).isPresent){
            throw Exception("That user exists already.")
        }

        val nuevoUserRegisterDTO = UsuarioDTO(
                            username = usuarioInsertadoDTO.username,
                            email = usuarioInsertadoDTO.email,
                            rol = usuarioInsertadoDTO.rol,
                            direccion = usuarioInsertadoDTO.direccion)


        val nuevoUser = Usuario(
                _id = null,
                username = usuarioInsertadoDTO.username,
                email = usuarioInsertadoDTO.email,
                password = passwordEncoder.encode(usuarioInsertadoDTO.password),
                roles = usuarioInsertadoDTO.rol.toString(),
                direccion = usuarioInsertadoDTO.direccion
        )


        usuarioRepository.insert(nuevoUser)
        return nuevoUserRegisterDTO
    }
}