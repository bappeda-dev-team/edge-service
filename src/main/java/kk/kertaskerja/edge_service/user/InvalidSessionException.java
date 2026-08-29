package kk.kertaskerja.edge_service.user;

public class InvalidSessionException extends RuntimeException {
    public InvalidSessionException() {
        super("Invalid session");
    }
}
