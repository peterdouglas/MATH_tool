from pathlib import Path
from typing import List

from tealer.detectors.abstract_detector import AbstractDetector, DetectorType
from tealer.teal.basic_blocks import BasicBlock
from tealer.teal.instructions.transaction_field import TypeEnum
from tealer.teal.instructions.instructions import Global, BDiv, BMul, Itob, Gtxn, AppGlobalGet, AppGlobalGetEx, Mul, Mulw, Sub, BSubtract, Add, Addw, BAdd, BModulo, BZero, Dup, AppLocalPut
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
        self.math_start = []

    def _getLastItem(self, list):
        if len(list) > 0:
            return list[len(list) - 1]
        return None
    
    def _isMath(self, ins):
        if isinstance(ins, (Mul, Mulw, BMul, BDiv, Sub, BModulo, BSubtract, Add, 
                            Addw, BAdd, BZero, Dup)):
            return True
        return False
    
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
        math_stack = []
        for ins in bb.instructions:
            stack_ins = self._getLastItem(math_stack)

            if ins._comment == '// 1':
                if not isinstance(ins._prev[0], Global) and not (
                    isinstance(ins._prev[0],Gtxn) and isinstance(ins._prev[0].field,
                                                                  TypeEnum)):
                    math_stack = []
                    math_stack.append(ins)
                continue
            
            if stack_ins is None:
                continue

            if isinstance(ins, Itob) and stack_ins._comment =='// 1':
                math_stack.append(ins)
                continue

            if isinstance(ins, (AppGlobalGet, AppGlobalGetEx)):
                if isinstance(stack_ins, Itob) or stack_ins._comment == '// 1':
                    math_stack.append(ins)
                else: 
                    math_stack = []
                continue
            
            if self._isMath(ins):
                if isinstance(ins, (Mul, Mulw, BMul)):
                    if isinstance(stack_ins, (AppGlobalGet, AppGlobalGetEx)):
                        math_stack.append(ins)

                else:
                    math_stack = []
                continue
            
            if isinstance(ins, AppLocalPut):
                if isinstance(stack_ins, (Mul, Mulw, BMul)):
                    math_stack.append(ins)
                    #if math_stack[0]._line not in self.math_start:
                    #    self.math_start.append(math_stack[0]._line)
                    print('Mathsploit found starting on line: ', 
                              math_stack[0]._line) 
                    has_mathploit = True
                else:
                    math_stack = []
                continue
                
        else:   
            if has_mathploit:
                print('found mathploit')
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
