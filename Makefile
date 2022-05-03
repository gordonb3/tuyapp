.PHONY : examples


EXAMPLES = simple_energy_monitor simple_switch tuya_switch tuya_kwh_meter tuya_status tuya_multi_kwh_meter


examples: examples/CMakeCache.txt
	make -C examples $(EXAMPLES)

examples/CMakeCache.txt:
	cmake -B examples -Sexamples

clean:
	rm -rf examples/CMakeFiles
	rm -f examples/CMakeCache.txt
	rm -f examples/*.cmake
	rm -f examples/Makefile
	rm -f $(EXAMPLES)
	rm -r -f *.a
	rm -r -f *.o

