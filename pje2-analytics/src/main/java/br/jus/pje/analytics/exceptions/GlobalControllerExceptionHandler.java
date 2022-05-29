package br.jus.pje.analytics.exceptions;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalControllerExceptionHandler {

  private Logger log = LoggerFactory.getLogger(this.getClass());

  @ExceptionHandler(Exception.class)
  public ResponseEntity<String> defaultErrorHandler(HttpServletRequest req, Exception ex) {

    // TODO: Implementar log com os dados de usuário
    MDC.put("username", "NO USER");
    // Nome do método executado
    MDC.put("metodo", ex.getStackTrace()[0].getMethodName());
    // Tempo de excução do método
    MDC.put("execucao", 0 + " ms");
    // Informações da instância do serviço
    log.error("Request: " + req.getRequestURL() + " raised " + ex);
    ex.printStackTrace();

    return new ResponseEntity<>(ex.toString(), HttpStatus.INTERNAL_SERVER_ERROR);
  }

}
