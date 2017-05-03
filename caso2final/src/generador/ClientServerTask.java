package generador;

import java.io.IOException;

import cliente.Cliente;
import uniandes.gload.core.Task;

public class ClientServerTask extends Task {

	@Override
	public void execute() {
		Cliente cliente = new Cliente();
		
		try {
			cliente.inicioSesion();
			cliente.authServidor();
			cliente.authCliente();
			cliente.realizarConsulta("2");
			cliente.fin();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public void fail() {
		System.out.println("FAIL_TEST");
	}

	@Override
	public void success() {
		System.out.println("OK_TEST");
	}
}

