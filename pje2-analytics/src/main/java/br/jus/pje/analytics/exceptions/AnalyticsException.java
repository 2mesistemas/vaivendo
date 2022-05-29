package br.jus.pje.analytics.exceptions;

public class AnalyticsException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  public AnalyticsException() {
    super();
  }

  public AnalyticsException(String message) {
    super(message);
  }

  public AnalyticsException(String message, Throwable cause) {
    super(message, cause);
  }

  public AnalyticsException(Throwable cause) {
    super(cause);
  }

}
