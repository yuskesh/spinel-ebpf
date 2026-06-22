# arena singly-linked list — arena_list_push / arena_list_sum.
@sum = 0

def tc__ingress__listdemo
  arena_list_push(10)
  arena_list_push(20)
  arena_list_push(30)
  @sum = arena_list_sum()
  TC_ACT_OK
end
