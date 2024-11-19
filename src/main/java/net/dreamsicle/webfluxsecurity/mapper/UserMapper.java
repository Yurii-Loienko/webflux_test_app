package net.dreamsicle.webfluxsecurity.mapper;

import net.dreamsicle.webfluxsecurity.dto.UserDto;
import net.dreamsicle.webfluxsecurity.entity.UserEntity;
import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserDto map(UserEntity userEntity);

    @InheritInverseConfiguration
    UserEntity map(UserDto userDto);
}
