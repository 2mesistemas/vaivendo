package br.jus.pje.analytics.exceptions;

public class ServiceDefaultException extends Exception {
  private static final long serialVersionUID = 1L;

  public ServiceDefaultException() {
    super();
  }

  public ServiceDefaultException(String message) {
    super(message);
  }

  public ServiceDefaultException(String message, Throwable cause) {
    super(message, cause);
  }

  public ServiceDefaultException(Throwable cause) {
    super(cause);
  }

}
