/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.opinion;

import java.io.*;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class TexasInstrumentsTxtLoader extends AbstractProgramLoader {

	public final static String TI_TXT_NAME = "Texas Instruments Text";

	@Override
	public LoaderTier getTier() {
		return LoaderTier.UNTARGETED_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return true;
	}

	private static final String OPTION_NAME_BASE_ADDRESS = "Base Address";
	private static final String OPTION_NAME_BLOCK_NAME = "Block Name";
	private static final String OPTION_NAME_IS_OVERLAY = "Overlay";

	private final static int BUFSIZE = 64 * 1024;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (isPossibleTxtFile(provider)) {
			loadSpecs.add(new LoadSpec(this, 0,
						new LanguageCompilerSpecPair("TI_MSP430:LE:16:default", "default"), true));
			loadSpecs.add(new LoadSpec(this, 0,
						new LanguageCompilerSpecPair("TI_MSP430X:LE:32:default", "default"), true));
		}
		return loadSpecs;
	}

	static boolean isPossibleTxtFile(ByteProvider provider) {
		try (BoundedBufferedReader reader =
			new BoundedBufferedReader(new InputStreamReader(provider.getInputStream(0)))) {
			String line = reader.readLine();
			while (line.matches("^\\s*$")) {
				line = reader.readLine();
			}
			return line.matches("^@[0-9a-fA-F]+$");
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		Address baseAddr = null;

		for (Option option : options) {
			String optName = option.getName();
			try {
				if (optName.equals(OPTION_NAME_BASE_ADDRESS)) {
					baseAddr = (Address) option.getValue();
					if (baseAddr == null) {
						return "Invalid base address";
					}
				}
				else if (optName.equals(OPTION_NAME_BLOCK_NAME)) {
					if (!String.class.isAssignableFrom(option.getValueClass())) {
						return OPTION_NAME_BLOCK_NAME + " must be a String";
					}
				}
				else if (optName.equals(OPTION_NAME_IS_OVERLAY)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						return OPTION_NAME_IS_OVERLAY + " must be a boolean";
					}
				}
				else {
					return "Unknown option: " + optName;
				}
			}
			catch (ClassCastException e) {
				return "Invalid type for option: " + optName + " - " + e.getMessage();
			}
		}
		return null;
	}

	private Address getBaseAddr(List<Option> options) {
		Address baseAddr = null;
		for (Option option : options) {
			String optName = option.getName();
			if (optName.equals(OPTION_NAME_BASE_ADDRESS)) {
				baseAddr = (Address) option.getValue();
			}
		}
		return baseAddr;
	}

	private String getBlockName(List<Option> options) {
		String blockName = "";
		for (Option option : options) {
			String optName = option.getName();
			if (optName.equals(OPTION_NAME_BLOCK_NAME)) {
				blockName = (String) option.getValue();
			}
		}
		return blockName;
	}

	private boolean isOverlay(List<Option> options) {
		boolean isOverlay = false;
		for (Option option : options) {
			String optName = option.getName();
			if (optName.equals(OPTION_NAME_IS_OVERLAY)) {
				isOverlay = (Boolean) option.getValue();
			}
		}
		return isOverlay;
	}

	@Override
	protected List<Loaded<Program>> loadProgram(ByteProvider provider, String programName,
			Project project, String programFolderPath, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Object consumer, TaskMonitor monitor)
			throws IOException, LoadException, CancelledException {
		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
		CompilerSpec importerCompilerSpec =
			importerLanguage.getCompilerSpecByID(pair.compilerSpecID);

		Program prog = createProgram(provider, programName, null, getName(), importerLanguage,
			importerCompilerSpec, consumer);
		List<Loaded<Program>> loadedList =
			List.of(new Loaded<>(prog, programName, programFolderPath));
		boolean success = false;
		try {
			loadInto(provider, loadSpec, options, log, prog, monitor);
			createDefaultMemoryBlocks(prog, importerLanguage, log);
			success = true;
			return loadedList;
		}
		finally {
			if (!success) {
				release(loadedList, consumer);
			}
		}
	}

	@Override
	protected void loadProgramInto(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, MessageLog log, Program prog, TaskMonitor monitor)
			throws IOException, LoadException, CancelledException {
		try {
			processTIText(provider, options, log, prog, monitor);
		}
		catch (AddressOverflowException e) {
			throw new LoadException(
				"Txt file specifies range greater than allowed address space - " + e.getMessage());
		}
	}

	private void processTIText(ByteProvider provider, List<Option> options, MessageLog log,
			Program program, TaskMonitor monitor)
			throws IOException, AddressOverflowException, CancelledException {
		String blockName = getBlockName(options);
		boolean isOverlay = isOverlay(options);
		Address baseAddr = getBaseAddr(options);
		if (baseAddr == null) {
			baseAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		}

		if (blockName == null || blockName.length() == 0) {
			blockName = generateBlockName(program, isOverlay, baseAddr.getAddressSpace());
		}

		long startAddress = 0;
		int offset = 0;
		String line;
		int lineNum = 0;
		byte[] dataBuffer = new byte[BUFSIZE];
		try (BufferedReader in =
			new BufferedReader(new InputStreamReader(provider.getInputStream(0)))) {
			while ((line = in.readLine()) != null) {
				monitor.checkCancelled();

				int index = 0;
				int temp;

				lineNum++;
				if (lineNum % 1000 == 0) {
					monitor.setMessage("Reading in ... " + lineNum);
				}

				line = line.trim();

				if (line.length() < 1) {
					log.appendMsg(provider.getName() + ", line " + lineNum + " is too short");
					continue;
				}

				boolean isEnd = false;
				boolean isSection = false;

				switch (line.charAt(0)) {
					case 'q':
					case 'Q':
						isEnd = true;
						break;
					case '@':
						isSection = true;
						break;
					default:
						break;
				}

				if (isEnd && line.length() > 1) {
					log.appendMsg(provider.getName() + ", garbage following 'q' marker on line " + lineNum);
				}

				if (isEnd || isSection || (offset + 16) > BUFSIZE) {
					if (offset != 0) {
						byte[] data = new byte[offset];
						System.arraycopy(dataBuffer, 0, data, 0, offset);

						Address start = baseAddr.add(startAddress);

						String name =
							blockName == null ? baseAddr.getAddressSpace().getName() : blockName;
						MemoryBlockUtils.createInitializedBlock(program, isOverlay, name, start,
								new ByteArrayInputStream(data), data.length, "", provider.getName(),
								true, isOverlay, isOverlay, log, monitor);

						log.appendMsg(provider.getName() + ", appending block of size " + offset +
								" bytes at address 0x" + Long.toHexString(start.getOffset()));
					}
					offset = 0;
				}

				if (isSection) {
					// The start address is encoded as a set of hex digits following the '@' sign.
					startAddress = NumericUtilities.parseHexLong(line.substring(1));
				}
				else if (isEnd) {
					break;
				}
				else {
					// Read at most 16 pairs of hex digits, separated by a single white space.
					for (int i = 0; i < 16 && index < line.length(); i++) {
						try {
							temp = getByte(line, index);
							index += 3;
						}
						catch (NumberFormatException exc) {
							log.appendMsg(provider.getName() + ", invalid number format at line " +
									+ lineNum + ", byte #" + i);
							break;
						}
						dataBuffer[offset++] = (byte) temp;
					}
				}
			}
		}
	}

	/**
	 * Returns a byte at the index in the line, formatted as an int.
	 */
	private int getByte(String line, int index) {
		int value;

		String byteString = line.substring(index, index + 2);
		value = Integer.parseInt(byteString, 16);
		return value;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		String blockName = "";
		boolean isOverlay = false;
		Address baseAddr = null;
		if (domainObject instanceof Program) {
			Program program = (Program) domainObject;
			AddressFactory addressFactory = program.getAddressFactory();
			if (addressFactory != null) {
				AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();
				if (defaultAddressSpace != null) {
					baseAddr = defaultAddressSpace.getAddress(0);
				}
			}
		}

		ArrayList<Option> list = new ArrayList<Option>();

		if (loadIntoProgram) {
			list.add(new Option(OPTION_NAME_IS_OVERLAY, isOverlay));
			list.add(new Option(OPTION_NAME_BLOCK_NAME, blockName));
		}
		else {
			isOverlay = false;
		}
		if (baseAddr == null) {
			list.add(new Option(OPTION_NAME_BASE_ADDRESS, Address.class));
		}
		else {
			list.add(new Option(OPTION_NAME_BASE_ADDRESS, baseAddr));
		}
		return list;
	}

	@Override
	public String getName() {
		return TI_TXT_NAME;
	}

}
