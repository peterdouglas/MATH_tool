from pathlib import Path
from typing import List

from tealer.detectors.abstract_detector import AbstractDetector, DetectorType
from tealer.teal.basic_blocks import BasicBlock
from tealer.teal.instructions.instructions import BSubtract, Txna, Return, Int
from tealer.teal.instructions.transaction_field import ApplicationArgs
from tealer.teal.teal import Teal


class Result:  # pylint: disable=too-few-public-methods
    def __init__(self, filename: Path, path_initial: List[BasicBlock], idx: int):
        self.filename = filename
        self.paths = [path_initial]
        self.idx = idx

    @property
    def all_bbs_in_paths(self) -> List[BasicBlock]:
        return [p for sublist in self.paths for p in sublist]


class byteSubtract(AbstractDetector):  # pylint: disable=too-few-public-methods

    NAME = "byteSubtract"
    DESCRIPTION = "Detect paths with a potentially problematic byte subtracting"
    TYPE = DetectorType.STATEFULLGROUP

    def __init__(self, teal: Teal):
        super().__init__(teal)
        self.results_number = 0
        self.count = 0
        self.blockStart = []
        self.blockChunks = []

    def _check_byte_subtract(
        self,
        bb: BasicBlock,
        current_path: List[BasicBlock],
        # use_gtnx: bool,
        all_results: List[Result],
    ) -> None:
        # check for loops
        if bb in current_path:
            return

        current_path = current_path + [bb]
        has_appArgs = False
        has_bSub = False
        arg_prev = []
        for ins in bb.instructions:
            if isinstance(ins, Txna):
                if isinstance(ins._field, ApplicationArgs):
                    has_appArgs = True
                    arg_prev = ins.prev[0]
    
            
            if not has_appArgs:
                continue

            if isinstance(ins, Return):
                if len(ins.prev) == 1:
                    prev = ins.prev[0]
                    if isinstance(prev, Int) and prev.value == 0:
                        return

            if isinstance(ins, BSubtract):
                ins2 = ins.prev[0]

                if isinstance(ins2, Txna) and not has_bSub:
                    nextIns = ins.next[0]
                    
                    if isinstance(ins2._field, ApplicationArgs):
                        for line_num in self.blockStart:
    
                            if int(line_num) == int(arg_prev._line):
                                break
                                
                        else:
                            has_bSub = True
                            self.count += 1
                            print('bSubtract found starting at line:', arg_prev._line)
                           

                            self.blockStart.append(int(arg_prev._line))
                            self.blockChunks.append([arg_prev, ins2, ins, nextIns])
                    
                        
                        continue
        else:   
            if has_bSub:
                filename = Path(f"byte_subtract_{self.results_number}.dot")
                self.results_number += 1
                all_results.append(Result(filename, current_path, self.results_number))

        for next_bb in bb.next:
            self._check_byte_subtract(next_bb, current_path, all_results)

    def detect(self) -> List[str]:

        all_results: List[Result] = []
        self._check_byte_subtract(self.teal.bbs[0], [], all_results)
        all_results_txt: List[str] = []
        for res in all_results:
            description = "Byte Subtraction with user input found\n"
            description += f"\tCheck the paths in {res.filename}\n"
            description += (
                "\tEnsure that empty string's are caught, as the byte substract treats n - n as '', not 0\n"
            )

            all_results_txt.append(description)
            self.teal.bbs_to_dot(res.filename, res.all_bbs_in_paths)

        return all_results_txt
