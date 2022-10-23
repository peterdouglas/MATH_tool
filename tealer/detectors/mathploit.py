from pathlib import Path
from typing import List

from tealer.detectors.abstract_detector import AbstractDetector, DetectorType
from tealer.teal.basic_blocks import BasicBlock
from tealer.teal.instructions.instructions import Bytec, Bytec0, Bytec1, Bytec2, Bytec3, BDiv, BMul, Itob, AppGlobalGet, AppGlobalGetEx
from tealer.teal.teal import Teal


class Result:  # pylint: disable=too-few-public-methods
    def __init__(self, filename: Path, path_initial: List[BasicBlock], idx: int):
        self.filename = filename
        self.paths = [path_initial]
        self.idx = idx

    @property
    def all_bbs_in_paths(self) -> List[BasicBlock]:
        return [p for sublist in self.paths for p in sublist]


class by1Math(AbstractDetector):  # pylint: disable=too-few-public-methods

    NAME = "by1 Exploit"
    DESCRIPTION = "Detect instances of the exploitable math found in a recent exploit"
    TYPE = DetectorType.STATEFULLGROUP

    def __init__(self, teal: Teal):
        super().__init__(teal)
        self.results_number = 0
        self.count = 0
        self.blockStart = []
        self.blockChunks = []

    def _check_by1(
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
        has_mathploit = False
        arg_prev = []
        for ins in bb.instructions:
            if ins._comment == '// 1':
                arg_prev = []
                for line_num in self.blockStart:
                    if int(line_num) == int(ins.prev[0]._line):
                        break
                else:
                    arg_prev.append(ins.prev[0])
                    arg_prev.append(ins)
                    continue

            if isinstance(ins, Itob):
                if len(arg_prev) > 1:
                    arg_prev.append(ins)
                    continue
            
            if isinstance(ins, (Bytec, Bytec0, Bytec1, Bytec2, Bytec3)):
                if len(arg_prev) > 1:
                    arg_prev.append(ins)
                    continue
            

            if isinstance(ins, (AppGlobalGet, AppGlobalGetEx)):
                if len(arg_prev) > 1:
                    arg_prev.append(ins)
                    continue

            if isinstance(ins, (BDiv, BMul)) and len(arg_prev) > 3:
                arg_prev.append(ins)
                print('Mathsploit found starting on line: ', arg_prev[0]._line)
                self.blockStart.append(arg_prev[0]._line)
                self.blockChunks.append(arg_prev)
                has_mathploit = True
                #for inst in arg_prev:
                #    print(inst._line, inst, inst._comment)
                
            arg_prev = []
        else:   
            if has_mathploit:
                filename = Path(f"math_exploit_{self.results_number}.dot")
                self.results_number += 1
                all_results.append(Result(filename, current_path, self.results_number))

        for next_bb in bb.next:
            self._check_by1(next_bb, current_path, all_results)

    def detect(self) -> List[str]:

        all_results: List[Result] = []
        self._check_by1(self.teal.bbs[0], [], all_results)
        all_results_txt: List[str] = []
        for res in all_results:
            description = "Math exploit with smart contract storage found\n"
            description += f"\tCheck the paths in {res.filename}\n"
            description += (
                "\tPlease review the specified segment, as potential math exploit has been detected\n"
            )

            all_results_txt.append(description)
            self.teal.bbs_to_dot(res.filename, res.all_bbs_in_paths)

        return all_results_txt
