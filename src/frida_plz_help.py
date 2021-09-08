import sys
import frida
import keyboard

main_script = """
		var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
		var range;
		function processNext(){
			range = ranges.pop();
			if(!range){
				// we are done
				return;
			}
			// due to the lack of blacklisting in Frida, there will be 
			// always an extra match of the given pattern (if found) because
			// the search is done also in the memory owned by Frida.
			Memory.scan(range.base, range.size, '%s', {
				onMatch: function(address, size){
						console.log('[+] Pattern found at: ' + address.toString());
					}, 
				onError: function(reason){
						console.log('[!] There was an error scanning memory');
					}, 
				onComplete: function(){
						processNext();
					}
				});
		}
		processNext();
"""


class Injector:
    def __init__(self):
        self.addresses = []

    def on_message(self, message, data):
        self.addresses.append(data)
        print("[%s] -> %s" % (message, data))
        print(self.addresses)

    def load(self, target_process, pattern):
        session = frida.attach(target_process)
        script = session.create_script("""
                var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
                var range;
                function processNext(){
                    range = ranges.pop();
                    if(!range){
                        // we are done
                        return;
                    }
                    // due to the lack of blacklisting in Frida, there will be 
                    // always an extra match of the given pattern (if found) because
                    // the search is done also in the memory owned by Frida.
                    Memory.scan(range.base, range.size, '%s', {
                        onMatch: function(address, size){
                                console.log(address.toString());
                            }, 
                        onError: function(reason){
                                console.log('[!] There was an error scanning memory');
                            }, 
                        onComplete: function(){
                                processNext();
                            }
                        });
                }
                processNext();
        """ % pattern)

        script.on('message', self.on_message)
        script.load()

        while not keyboard.is_pressed('`'):
            pass

        script.detach()


if __name__ == '__main__':
    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]
    except IndexError:
        target_process = 'BloonsTD6.exe'

    try:
        pattern = sys.argv[2]
    except IndexError:
        pattern = '48 8B 43 28 F2 0F11 73'

    inj = Injector()
    inj.load(target_process, pattern)
