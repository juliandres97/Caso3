package generador;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {
	
	private LoadGenerator generator;
	
	public Generator() {
		Task work = createTask();
		int numberofTasks = 100;
		int gapBetweenTasks = 1000;
		generator = new LoadGenerator("Cliente - Servidor (Load Test)", numberofTasks, work, gapBetweenTasks);
		generator.generate();
	}
	
	private Task createTask() {
		return new ClientServerTask();
	}
	
	public static void main(String[] args) {
		Generator gen = new Generator();
	}
}
