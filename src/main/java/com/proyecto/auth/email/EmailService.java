package com.proyecto.auth.email;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender mailSender;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    @Value("${app.mail.from}")
    private String mailFrom;

    @Async
    public void enviarEmailConfirmacion(String emailDestino, String token) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "utf-8");

            // Asegurate de cambiar localhost por la URL real de tu front cuando vayas a producción
            String linkConfirmacion = frontendUrl + "/confirmar?token=" + token;

            String htmlMsg = "<div style='font-family: Arial, sans-serif; padding: 20px; text-align: center;'>"
                    + "<h2 style='color: #0f172a;'>¡Bienvenido a ENTRIXPASS!</h2>"
                    + "<p style='color: #475569;'>Estamos muy contentos de tenerte con nosotros.</p>"
                    + "<p style='color: #475569;'>Para activar tu cuenta y empezar, por favor confirmá tu correo electrónico:</p>"
                    + "<a href='" + linkConfirmacion + "' style='display: inline-block; background-color: #0284c7; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 6px; font-weight: bold; margin-top: 20px;'>Confirmar mi cuenta</a>"
                    + "<p style='color: #94a3b8; font-size: 12px; margin-top: 30px;'>Este enlace expira en 12 horas.</p>"
                    + "</div>";

            helper.setText(htmlMsg, true);
            helper.setTo(emailDestino);
            helper.setSubject("Activá tu cuenta de ENTRIXPASS");
            helper.setFrom(mailFrom);

            mailSender.send(message);

        } catch (MessagingException e) {
            System.err.println("Error al enviar el email de confirmación a " + emailDestino);
            e.printStackTrace();
        }
    }

    @Async
    public void enviarEmailRecuperacion(String emailDestino, String token) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "utf-8");

            // Apunta a la futura pantalla de tu front
            String linkRecuperacion = frontendUrl + "/restablecer?token=" + token;

            String htmlMsg = "<div style='font-family: Arial, sans-serif; padding: 20px; text-align: center;'>"
                    + "<h2 style='color: #0f172a;'>Recuperación de Contraseña</h2>"
                    + "<p style='color: #475569;'>Recibimos una solicitud para restablecer tu contraseña en ENTRIXPASS.</p>"
                    + "<a href='" + linkRecuperacion + "' style='display: inline-block; background-color: #0284c7; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 6px; font-weight: bold; margin-top: 20px;'>Restablecer Contraseña</a>"
                    + "<p style='color: #94a3b8; font-size: 12px; margin-top: 30px;'>Si no solicitaste esto, ignorá este correo. El enlace expira en 2 horas.</p>"
                    + "</div>";

            helper.setText(htmlMsg, true);
            helper.setTo(emailDestino);
            helper.setSubject("Restablecé tu contraseña - ENTRIXPASS");
            helper.setFrom(mailFrom);

            mailSender.send(message);

        } catch (MessagingException e) {
            System.err.println("Error al enviar email de recuperación a " + emailDestino);
        }
    }
}
