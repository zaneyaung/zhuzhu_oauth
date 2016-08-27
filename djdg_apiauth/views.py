# Create your views here.
# -*- coding: utf-8 -*-
import json
from rest_framework import viewsets
from .models import Group, ApiPermission
from .serializers import GroupSerializer, ApiPermissionSerializer


class GroupHandler(viewsets.ModelViewSet):
    """
    权限组操作
    """

    queryset = Group.objects.all()
    serializer_class = GroupSerializer

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def get(self, request, *args, **kwargs):
        data_format = request.GET.get('format')
        groups = self.model.objects.all()
        python_dict = serializers.serialize('python', groups)
        data = {"statusCode": 0}
        data['groups'] = python_dict
        if data_format == 'json':
            return JSONResponse({'data': data})
        return render_to_response('permission/group_list.html', RequestContext(request, {'data': data}))

    def post(self, request, *args, **kwargs):
        data = json.loads(request.body.decode('UTF-8'))
        name = data.get('name')
        if name:
            group, created = self.model.objects.get_or_create(name=name)
            apipermission_ids = data.get('permission_ids', [])
            new_permissions = set(api_permission.objects.filter(pk__in=apipermission_ids))

            if new_permissions:
                for permission in new_permissions:
                    group_api, created = self.permission_model.objects.get_or_create(group=group, apipermission=permission)

            if created:
                return JSONResponse({"statusCode": 0, "msg": u"角色创建成功"})
            else:
                return JSONResponse({"statusCode": 4, "msg": u"角色已经存在"})
        else:
            return JSONResponse({"statusCode": 5, "msg": u"角色创建失败"})

class groupDetailHandler(View):
    '''
    permission : GET : 权限管理-角色管理-角色详情
    permission : PUT : 权限管理-角色管理-修改角色
    permission : DELETE : 权限管理-角色管理-删除角色
    '''
    model = api_group
    permission_model = api_group_permission

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def get(self, request, *args, **kwargs):
        pk = kwargs.get('pk')
        data_format = request.GET.get('format')
        try:
            group = self.model.objects.get(pk=int(pk))
            group = serializers.serialize('python', [group])[0]
            group_apipermission = getApiLeaf(parent_id=None, groups=[group['pk']], is_superuser=False)
            if data_format == 'json':
                return JSONResponse({'data': group, 'api_list': group_apipermission})

            return render_to_response('permission/group_detail.html', RequestContext(request,
                                                                          {'data': group,
                                                                           'api_list': group_apipermission}))

        except:
            return JSONResponse({"statusCode": 4, "msg": u"角色不存在"})

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    @method_decorator(atomic)
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body.decode('UTF-8'))
        name = data.get('name')
        apipermission_ids = data.get('permission_ids')
        action = data.get('action')
        pk = kwargs.get('pk')
        if not pk:
            return JSONResponse({"statusCode": 5, "msg": u"角色修改失败"})
        try:
            group = self.model.objects.get(pk=pk)
        except:
            return JSONResponse({"statusCode": 4, "msg": u"角色不存在"})
        if name:
            group.name = name
            group.save()
        add_permissions = set()
        del_permissions = set()

        if isinstance(apipermission_ids, list):
            #传递全部的apis
            old_permissions = set([ api.apipermission for api in self.permission_model.objects.filter(group=group)])
            new_permissions = set(api_permission.objects.filter(pk__in=apipermission_ids))
            add_permissions = new_permissions - old_permissions
            del_permissions = old_permissions - new_permissions

        elif isinstance(apipermission_ids, (int, str)):
            #传递单个数据
            api = api_permission.objects.get(pk=apipermission_ids)
            if action == 'add':
                add_permissions = set(api.get_family())
            elif action == 'delete':
                leaf_permissions = api.get_children()
                parent_permissions = api.get_ancestors()
                del_permissions = set(leaf_permissions)
                del_permissions.add(api)
                for p_p in parent_permissions:
                    _leaf_permissions = list(p_p.get_children())
                    if self.permission_model.objects.filter(group=group, apipermission__in=_leaf_permissions).exclude(apipermission=api):
                        continue
                    else:
                        del_permissions.add(p_p)
        elif action == 'add_all':
            old_permissions = set([ api.apipermission for api in self.permission_model.objects.filter(group=group)])
            new_permissions = set(api_permission.objects.all())
            add_permissions = new_permissions - old_permissions

        elif action == 'inverse':
            old_permissions = set([ api.apipermission for api in self.permission_model.objects.filter(group=group)])
            for o_p in old_permissions:
                o_p_children = o_p.get_children()
                if len(o_p_children) <= len(self.permission_model.objects.filter(group=group, apipermission__in=o_p_children)):
                    del_permissions.add(o_p.id)
            all_permission = set(api_permission.objects.all())
            add_permissions = all_permission - del_permissions


        if add_permissions:
            for permission in add_permissions:
                group_api, created = self.permission_model.objects.get_or_create(group=group, apipermission=permission)
        if del_permissions:
            del_per_obj = self.permission_model.objects.filter(apipermission__in=del_permissions).delete()
        return JSONResponse({"statusCode": 0, "msg": u"角色修改成功"})



    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def delete(self, request, *args, **kwargs):
        '''
        角色冻结
        '''
        pk = kwargs.get('pk')
        if pk:
            try:
                group = self.model.objects.get(pk=pk)
            except Exception, e:
                return JSONResponse({"statusCode": 5, "msg": u"角色不存在"})
            group.status = 0
            group.save()
            return JSONResponse({"statusCode": 0, "msg": u"角色冻结成功"})
        else:
            return JSONResponse({"statusCode": 1, "msg": u"角色冻结失败"})

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def patch(self, request, *args, **kwargs):
        '''
        角色解冻
        '''
        pk = kwargs.get('pk')
        if pk:
            try:
                group = self.model.objects.get(pk=pk)
            except Exception, e:
                return JSONResponse({"statusCode": 5, "msg": u"角色不存在"})
            group.status = 1
            group.save()
            return JSONResponse({"statusCode": 0, "msg": u"角色冻结成功"})
        else:
            return JSONResponse({"statusCode": 1, "msg": u"角色冻结失败"})

class groupRoleViewHandler(View):
    model = api_group
    permission_model = api_group_permission

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def get(self, request):
        pk = request.GET.get('pk')
        return render_to_response('permission/api_role_view.html', RequestContext(request,
                                                                      {'pk': pk}))


class groupRoleAddHandler(View):
    model = api_group
    permission_model = api_group_permission

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def get(self, request):
        return render_to_response('permission/api_role_add.html', RequestContext(request))


class groupRoleEditHandler(View):
    model = api_group
    permission_model = api_group_permission

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def get(self, request):
        pk = request.GET.get('pk')
        return render_to_response('permission/api_role_edit.html', RequestContext(request,
                                                                      {'pk': pk}))


class groupPowerEditHandler(View):
    '''
    permission : GET : 权限管理-角色管理-角色详情
    '''
    model = api_group
    permission_model = api_group_permission

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def get(self, request):
        return render_to_response('permission/api_power_edit.html', RequestContext(request))


class apiPermissionHandler(View):
    '''
    permission : GET : 权限管理-目录管理
    permission : POST : 权限管理-目录管理-新增目录
    '''

    api_model = api_permission
    model = api_group_permission

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def get(self, request, *args, **kwargs):
        data = request.GET
        group_id = data.get('group_id')
        data_format = data.get('format')
        groups = None
        if group_id:
            groups = api_group.objects.filter(pk=group_id)
        apis = getApiLeaf(None, groups, False)
        if data_format == 'json':
            return JSONResponse(apis)
        return render_to_response('permission/api_list.html')

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body.decode('UTF-8'))
        valid_fields = ('name', 'url', 'http_method', 'parent')
        for k, v in data.items():
            if k not in valid_fields:
                data,pop(k)
        api = self.api_model(**data)
        api.save()
        return JSONResponse({"statusCode": 0, "msg": u"目录新增成功"})


class apiPermissionDetailHandler(View):
    '''
    permission : PUT : 权限管理-目录管理-修改目录
    permission : DELETE : 权限管理-目录管理-删除目录
    '''

    model = api_permission

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body.decode('UTF-8'))
        pk = kwargs.get('pk')
        if not pk:
            return JSONResponse({"statusCode": 0, "msg": u"目录修改失败"})
        valid_fields = ('name', 'url', 'http_method', 'parent')
        for k, v in data.items():
            if k not in valid_fields:
                data.pop(k)
        try:
            api = self.model.objects.filter(pk=pk)
        except Exception, e:
            return JSONResponse({"statusCode": 4, "msg": u"目录不存在"})
        api.update(**data)
        return JSONResponse({"statusCode": 0, "msg": u"目录修改成功"})

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def delete(self, request, *args, **kwargs):
        pk = kwargs.get('pk')
        if pk:
            try:
                api = self.model.objects.get(pk=pk)
            except Exception, e:
                return JSONResponse({"statusCode": 5, "msg": u"角色不存在"})
            api.delete()
            return JSONResponse({"statusCode": 0, "msg": u"角色删除成功"})
        else:
            return JSONResponse({"statusCode": 4, "msg": u"角色删除失败"})

@login_required
def userPermissionList(request):
    user = request.user
    if user.is_superuser:
        api_list = getUserApiLeaf(None, None, True)
    else:
        groups = api_group.objects.filter(user_groups__user=user, status=1)
        api_list = getUserApiLeaf(None, groups, False)
    return JSONResponse({"api_list": api_list})

def getUserApiLeaf(parent_id, groups, is_superuser):
    apis = api_permission.objects.filter(parent_id=parent_id, is_tab=1)
    json_apis = serializers.serialize('python', apis)
    for api in json_apis:
        if is_superuser:
            api['status'] = 1
        else:
            api['status'] = 0
            if groups:
                api['status'] = 1 if api_permission.objects.filter(group_apipermission__group__in=groups, group_apipermission__apipermission__pk=api['pk']) else 0
        api['sub_api'] = getUserApiLeaf(parent_id=api['pk'], groups=groups, is_superuser=is_superuser)
        if not api['fields'].get('url'):
            api['fields']['url'] = getSubUrl([ _api for _api in api['sub_api'] if _api['status']])
    return json_apis


def getApiLeaf(parent_id=None, groups=None, is_superuser=False):
    apis = api_permission.objects.filter(parent_id=parent_id)
    json_apis = serializers.serialize('python', apis)
    for api in json_apis:
        if is_superuser:
            api['status'] = 1
        else:
            api['status'] = 0
            if groups:
                api['status'] = 1 if api_permission.objects.filter(group_apipermission__group__in=groups, group_apipermission__apipermission__pk=api['pk']) else 0
        api['sub_api'] = getApiLeaf(parent_id=api['pk'], groups=groups, is_superuser=is_superuser)
    return json_apis

def getSubUrl(apis):
    urls = [api['fields']['url'] for api in apis]
    if urls:
        return urls[0]
    else:
        for api in apis:
            url = getSubUrl([ _api for _api in api['sub_api'] if _api['status']])
            if url:
                return url
        else:
            return ''



class userListHandler(View):
    '''
    permission : GET : 权限管理-用户管理
    permission : POST : 权限管理-用户管理-用户新增
    '''

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def get(self, request, *args, **kwargs):
        page = int(request.GET.get('page', 1))
        limit = int(request.GET.get('limit', 50))
        data_format = request.GET.get('format')
        keyword = request.GET.get('keyword', '')
        group_id = request.GET.get('group_id')
        region_id = request.GET.get('region', -1)

        filter_dict = {'is_superuser': False, 'is_staff': True}
        if group_id and int(group_id) > 0:
            filter_dict['autho2o_group__group__id'] = group_id
        if region_id and int(region_id) > 0:
            filter_dict['auth_user__region__id'] = region_id
        data = User.objects.filter(**filter_dict)
        if keyword != '':
            data = data.filter(Q(username__icontains=keyword) | Q(auth_user__name__icontains=keyword))

        result = json_page(data, limit, page)
        data_arr = []

        for item in result['data']:
            user = User.objects.get(pk=item.id)
            group = [{'id': g.group.id, 'name': g.group.name} for g in user.autho2o_group.all()]
            # group = list(user.autho2o_group.all().values('group_id', 'group__name'))
            try:
                user_profile = list(UserProfile.objects.filter(user=user).values('tel', 'name', 'region_id', 'region__name'))[0]
            except:
                user_profile = {}
            data_arr.append({'id': item.id, 'username': item.username, 'first_name': item.first_name,
                             # 'last_login': item.last_login.strftime('%Y-%m-%d %H:%M:%S'),
                             'date_joined': item.date_joined.strftime('%Y-%m-%d %H:%M:%S'),
                             'is_superuser': item.is_superuser, 'is_staff': item.is_staff, 'is_active': item.is_active,
                             'email': item.email, 'group': group, 'user_profile': user_profile})
        result['data'] = data_arr
        if data_format == 'json':
            return JSONResponse(result)
        return render_to_response('permission/user_list.html', RequestContext(request,
                                                                      {'data': result}))

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    @method_decorator(atomic)
    def post(self, request, *args, **kwargs):
        json_string = request.body.decode('UTF-8')
        data = json.loads(json_string)
        user_name = data.get('account_name', '')
        first_name = data.get('first_name', '')
        profile_name = data.get('username', '')
        tel = data.get('tel', '')
        region_id = data.get('region_id')
        email = data.get('email', '')
        password = data.get('password', '')
        super_user = data.get('super_user', 'false')
        groups = data.get("groups", "")
        group_ids = [item['id'] for item in groups]
        groups = api_group.objects.filter(pk__in=group_ids)

        if not user_name or not password:
            return JSONResponse({"statusCode": 2, "msg": u"用户数据不全"})

        try:
            if super_user == 'true':
                user = User.objects.create_superuser(username=user_name, is_staff=True, first_name=first_name,
                                                     email=email, password=password)
            else:
                user = User.objects.create_user(username=user_name, is_staff=True, first_name=first_name,
                                                email=email, password=password)
            for group in groups:
                user_group = api_user_group(user=user, group=group)
                user_group.save()
            if region_id and int(region_id) > 0:
                region = Region.objects.get(pk=region_id)
            else:
                region = None
            up, created = UserProfile.objects.get_or_create(user=user)
            up.name = profile_name if profile_name else user_name
            up.tel = tel
            up.region = region
            up.save()

            return JSONResponse({"statusCode": 0, "msg": u"用户保存成功"})
        except IntegrityError:
            return JSONResponse({"statusCode": 4, "msg": u"用户名称已经存在"})

class userDetailHandler(View):

    '''
    permission : GET : 权限管理-用户管理-用户详情
    permission : PUT : 权限管理-用户管理-用户修改
    permission : DELETE : 权限管理-用户管理-用户删除
    '''

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def get(self, request, *args, **kwargs):
        pk = kwargs.get("pk", 0)
        data_format = request.GET.get('format')
        try:
            user = User.objects.get(pk=pk)
            group = user.autho2o_group.all()
            try:
                user_profile = list(UserProfile.objects.filter(user=user).values('name', 'tel', 'region_id', 'region__name'))[0]
            except:
                user_profile = {}
            group_arr = [{'id': g.group.id, 'name': g.group.name} for g in group]

            data_arr = {'id': user.id, 'username': user.username, 'first_name': user.first_name,
                             # 'last_login': item.last_login.strftime('%Y-%m-%d %H:%M:%S'),
                             'date_joined': user.date_joined.strftime('%Y-%m-%d %H:%M:%S'),
                             'is_superuser': user.is_superuser, 'is_staff': user.is_staff, 'is_active': user.is_active,
                             'email': user.email, 'group': group_arr, 'user_profile': user_profile}
            if data_format == 'json':
                return JSONResponse(data_arr)

            return render_to_response('permission/user_detail.html', RequestContext(request,
                                                                          {'data': data_arr}))
        except:
            return JSONResponse({"statusCode": 4, "msg": u"用户不存在"})

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    @method_decorator(atomic)
    def put(self, request, *args, **kwargs):
        json_string = request.body.decode('UTF-8')
        data = json.loads(json_string)
        pk = kwargs.get("pk", 0)
        try:
            user_args = {'account_name', 'first_name', 'email'}
            userprofile_args = {'username', 'tel', 'region_id'}
            user_dict = {}
            uprofile_dict = {}
            for key, v in data.items():
                if key in user_args:
                    if key == 'account_name':
                        key = 'username'
                    user_dict[key] = v
                elif key in userprofile_args:
                    if key == 'username':
                        key = 'name'
                    if key == 'region_id':
                        key = 'region'
                        try:
                            region_obj = Region.objects.get(pk=v)
                        except:
                            region_obj = None
                        v = region_obj
                    uprofile_dict[key] = v
            user = User.objects.get(pk=pk)
            if user_dict:
                for user_k, user_v in user_dict.items():
                    setattr(user, user_k, user_v)
                user.save()
            if uprofile_dict:
                # uprofile_dict['user'] = user
                user_profile, created = UserProfile.objects.update_or_create(user=user)
                for k, v in uprofile_dict.items():
                    setattr(user_profile, k, v)
                user_profile.save()


            exist_group = user.autho2o_group.all()
            exist_data = set([item.group_id for item in exist_group])
            new_data = set([item.get('id') for item in data['groups']])
            add_data = new_data - exist_data
            del_data = exist_data - new_data
            group_add = api_group.objects.filter(pk__in=add_data)
            group_del = api_group.objects.filter(pk__in=del_data)
            for del_g in group_del:
                user_group = api_user_group.objects.get(user=user, group=del_g)
                user_group.delete()
            for add_g in group_add:
                api_user_group.objects.get_or_create(user=user, group=add_g)
        except Exception, e:
            if isinstance(e, IntegrityError):
                return JSONResponse({"statusCode": 4, "msg": u"用户信息冲突. "+ e.args[1]})
            elif isinstance(e, User.DoesNotExist):
                return JSONResponse({"statusCode": 4, "msg": u"用户不存在"})
            else:
                return JSONResponse({"statusCode": 4, "msg": u"用户修改失败"})
        return JSONResponse({"statusCode": 0, "msg": u"用户修改成功"})

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    @method_decorator(atomic)
    def delete(self, request, *args, **kwargs):
        pk = kwargs.get('pk', 0)
        try:
            user = User.objects.get(pk=pk)
            user.is_active = False
            user.is_superuser = False
            user.save()

            ####revoke permission group####
            user_groups = api_user_group.objects.filter(user=user)
            for user_group in user_groups:
                user_group.delete()

        except User.DoesNotExist:
            return JSONResponse({"statusCode": 4, "msg": u"用户不存在"})

        return JSONResponse({"statusCode": 0, "msg": u"用户冻结成功"})


    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    @method_decorator(atomic)
    def patch(self, request, *args, **kwargs):
        pk = kwargs.get('pk', 0)
        try:
            user = User.objects.get(pk=pk)
            user.is_active = True
            user.is_staff = True
            user.save()

            ####revoke permission group####
            user_groups = api_user_group.objects.filter(user=user)
            for user_group in user_groups:
                user_group.delete()

        except User.DoesNotExist:
            return JSONResponse({"statusCode": 4, "msg": u"用户不存在"})

        return JSONResponse({"statusCode": 0, "msg": u"用户解冻成功"})


@login_required
@api_permission_required
def changeUserPassword(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('UTF-8'))
        user_id = data.get('user_id')
        password = data.get('password')
        if not password:
            return JSONResponse({"statusCode": 4, "msg": u"密码不能为空"})
        # try:
        user = User.objects.get(pk=user_id)
        user.set_password(password)
        user.save()
        return JSONResponse({"statusCode": 0, "msg": u"密码修改成功"})
        # except:
        #     return JSONResponse({"statusCode": 0, "msg": u"密码修改失败"})
    else:
        raise PermissionDenied


class groupRoleEditHandler(View):
    model = api_group
    permission_model = api_group_permission

    @method_decorator(login_required)
    @method_decorator(api_permission_required)
    def get(self, request):
        pk = request.GET.get('pk')
        return render_to_response('permission/api_role_edit.html', RequestContext(request,
                                                                      {'pk': pk}))


@login_required
@api_permission_required
def data_authorityview(request, userId):
    # supplier = Supplier.objects.get(pk=ppid);

    return render_to_response('permission/api_data_authorityview.html',
                              RequestContext(request, {
                                                       #  'supplierMenu': 'active',
                                                       # 'sellerMenu': 'active',
                                                       #  'supplier': supplier,
                                                       'pk':userId,
                                                       'permission': getPermmision(request)}))
